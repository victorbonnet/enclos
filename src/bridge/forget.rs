//! Forgetting a removed agent (ADR 0067, proposed): only an agent the
//! runtime's checks confirm gone, only by the host's person. Nothing native
//! is left, so no plugin is asked.
use super::*;
use crate::bridge::store::Forget;

#[cfg(test)]
#[path = "forget_tests.rs"]
mod tests;

fn refused(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody {
        of: None,
        code,
        message: message.into(),
    }
}

fn storage(error: rusqlite::Error) -> ErrorBody {
    eprintln!("enclos app: forgetting an agent: {error}");
    refused(
        ErrorCode::Internal,
        "Forget could not finish. Retry Forget.",
    )
}

impl Hub {
    /// The agents `person` has a Home or a direct conversation with that
    /// the runtime's no-follow checks confirm removed, with no identity or
    /// data left: those the app may offer to forget. Only the host's
    /// person forgets, so anyone else hears of none.
    pub(super) fn removed_agents(
        &self,
        store: &Store,
        person: &str,
    ) -> Result<Vec<String>, ErrorBody> {
        if self.known_host().as_deref() != Some(person) {
            return Ok(Vec::new());
        }
        let candidates = store.forget_candidates(person).map_err(|e| {
            eprintln!("enclos app: cannot list the agents to forget: {e}");
            refused(
                ErrorCode::Internal,
                "The removed agents could not be listed. Try again later.",
            )
        })?;
        Ok(candidates
            .into_iter()
            .filter(|agent| self.deletion_target_absent(agent))
            .collect())
    }

    /// Forgets `agent` (`<sandbox>/<agent>`) for the host's person, from a
    /// still-paired device of theirs: its Home and every direct
    /// conversation of theirs with it are deleted, and each of their
    /// devices told. Refused while the agent is not confirmed removed.
    pub(super) fn forget_agent(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
    ) -> Result<(), ErrorBody> {
        self.host_authority(store, device, person)
            .map_err(|(code, message)| refused(code, message))?;
        // Checked before the removal check, which takes the agent apart.
        let named = agent.split_once('/').is_some_and(|(sandbox, name)| {
            crate::model::sandbox::is_short_name(sandbox)
                && crate::model::sandbox::is_short_name(name)
        });
        if !named {
            return Err(refused(
                ErrorCode::BadMessage,
                "An agent is named <sandbox>/<agent>.",
            ));
        }
        if !self.deletion_target_absent(agent) {
            return Err(refused(
                ErrorCode::NotAllowed,
                format!(
                    "{agent} is not confirmed removed: its runtime identity or data may be left, or enclos cannot tell. Remove its sandbox with its folder first."
                ),
            ));
        }
        // Files first, while the rows that name them stay for a retry.
        for file in store.forget_files(agent, person).map_err(storage)? {
            self.remove_media(&file)?;
        }
        let (ids, files) = store
            .forget_agent(agent, person, &device.id)
            .map_err(|e| match e {
                Forget::Storage(e) => storage(e),
                Forget::OwnedByAnother(id) => {
                    eprintln!(
                        "enclos app: forgetting {agent}: conversation {id} has a deletion of another person's"
                    );
                    refused(
                        ErrorCode::Internal,
                        "Forget cannot finish: one of these conversations is in another person's deletion.",
                    )
                }
            })?;
        // Any a device added meanwhile: their rows are gone already, so a
        // file left now is said here, or nobody would find it.
        for file in files {
            if self.remove_media(&file).is_err() {
                eprintln!("enclos app: forgetting {agent}: attachment {file} is left in app media");
            }
        }
        let mut groups = self.groups.lock().expect("not poisoned");
        for id in &ids {
            groups.remove(id);
        }
        drop(groups);
        for id in ids {
            match ConversationId::new(id.as_str()) {
                Ok(conversation) => {
                    self.deliver(person, ToDevice::ConversationDeleted { conversation })
                }
                // Not one a device could have been told of either.
                Err(e) => eprintln!(
                    "enclos app: forgetting {agent}: conversation {id:?} deleted, but its id is refused ({e})"
                ),
            }
        }
        Ok(())
    }

    /// Removes attachment `file`, a bridge-made id, from the app's media:
    /// already gone is fine.
    fn remove_media(&self, file: &str) -> Result<(), ErrorBody> {
        if Path::new(file).components().count() != 1 || file == "." || file == ".." {
            return Err(refused(
                ErrorCode::Internal,
                "An attachment could not be removed.",
            ));
        }
        match std::fs::remove_file(self.media().join(file)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                eprintln!("enclos app: cannot remove attachment {file}: {e}");
                Err(refused(
                    ErrorCode::Internal,
                    "An attachment could not be removed. Retry Forget.",
                ))
            }
        }
    }
}
