//! One reviewed removal per device connection. Never persisted or replayed.

use super::provisioning::Operation;
use crate::engine::RemovalReview;
use enclos_protocol::MessageId;
use enclos_protocol::device::RemovalPreviewInfo;
use std::time::{Duration, Instant};

pub(super) struct Permit {
    token: String,
    review: RemovalReview,
    expires: Instant,
}

impl Permit {
    pub fn new(review: RemovalReview) -> Result<Self, String> {
        Ok(Self {
            token: super::ids::new_id().map_err(|error| error.to_string())?,
            review,
            expires: Instant::now() + Duration::from_secs(120),
        })
    }

    pub fn info(&self, of: MessageId) -> RemovalPreviewInfo {
        RemovalPreviewInfo {
            of,
            preview: self.token.clone(),
            revision: self.review.revision.clone(),
            kind: if self.review.agent.is_some() {
                "agent"
            } else {
                "sandbox"
            }
            .into(),
            sandbox: self.review.sandbox.to_string(),
            agent: self.review.agent.as_ref().map(ToString::to_string),
            runtime: self.review.runtime.map(|runtime| runtime.to_string()),
            agents: self.review.agents.clone(),
            secret_count: self.review.secret_count,
            session_count: self.review.session_count,
            services: self.review.services.clone(),
            effects: self.review.effects.clone(),
            expires_in: 120,
        }
    }

    pub fn consume(
        self,
        sandbox: &str,
        agent: Option<&str>,
        token: &str,
        confirmation: &str,
    ) -> Result<Operation, String> {
        if Instant::now() >= self.expires
            || token != self.token
            || sandbox != self.review.sandbox.as_str()
            || agent != self.review.agent.as_ref().map(|agent| agent.as_str())
        {
            return Err("This removal preview expired or no longer matches this connection and target. Review removal again.".into());
        }
        let expected = agent.unwrap_or(sandbox);
        if confirmation != expected {
            return Err(format!(
                "Type exactly {expected} to confirm. This preview is consumed; review removal again."
            ));
        }
        Ok(Operation::Remove {
            review: Box::new(self.review),
            preview: self.token,
        })
    }
}

#[cfg(test)]
pub(super) fn review_fixture() -> (tempfile::TempDir, RemovalReview) {
    use crate::{
        audit::jsonl::JsonlAuditLog,
        backend::fake::FakeBackend,
        engine::{Engine, SandboxSpec},
        layout::Layout,
        model::{audit::Actor, plan::Confirm, sandbox::BackendKind},
        service::fake::FakeServices,
        state::sqlite::SqliteStateStore,
    };
    let dir = tempfile::tempdir().unwrap();
    let layout = Layout::at(dir.path().join("enclos"));
    let engine = Engine::new(
        layout.clone(),
        Box::new(SqliteStateStore::new(
            layout.state_db(),
            layout.state_lock(),
        )),
        Box::new(JsonlAuditLog::new(layout.audit_log())),
        vec![Box::new(FakeBackend::available(BackendKind::Seatbelt))],
    )
    .with_services(Box::new(FakeServices::default()));
    let actor = Actor {
        user: "test".into(),
        host: "local".into(),
    };
    engine.init(&actor, Confirm::Yes).unwrap();
    let name = "lab".parse().unwrap();
    engine
        .create_sandbox(
            &actor,
            SandboxSpec {
                name,
                backend: BackendKind::Seatbelt,
                template: "assistant".parse().unwrap(),
            },
            Confirm::Yes,
        )
        .unwrap();
    let review = engine
        .removal_review(&"lab".parse().unwrap(), None)
        .unwrap();
    (dir, review)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permits_require_the_exact_connection_token_target_name_and_unexpired_review() {
        let (_dir, review) = review_fixture();
        for (sandbox, agent, token_wrong, confirmation, expired) in [
            ("lab", None, false, "lab", false),
            ("other", None, false, "other", false),
            ("lab", Some("scout"), false, "scout", false),
            ("lab", None, true, "lab", false),
            ("lab", None, false, "Lab", false),
            ("lab", None, false, "lab", true),
        ] {
            let mut permit = Permit::new(review.clone()).unwrap();
            let mut token = permit
                .info(MessageId::new("preview-request").unwrap())
                .preview;
            if token_wrong {
                token = Permit::new(review.clone()).unwrap().token;
            }
            if expired {
                permit.expires = Instant::now() - Duration::from_secs(1);
            }
            let valid = sandbox == "lab"
                && agent.is_none()
                && !token_wrong
                && confirmation == "lab"
                && !expired;
            let mut slot = Some(permit);
            assert_eq!(
                slot.take()
                    .unwrap()
                    .consume(sandbox, agent, &token, confirmation)
                    .is_ok(),
                valid
            );
            assert!(slot.take().is_none(), "a permit was replayable");
        }
    }
}
