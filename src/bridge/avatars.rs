//! Host-owned agent photos: decode a bounded raster, normalize it, then publish a versioned asset.
use super::super::store::StoredAvatar;
use super::*;
use enclos_protocol::avatar::{AgentAvatar, AvatarSet, MAX_AVATAR_BYTES};
use enclos_protocol::plugin::{ErrorBody, ErrorCode};

pub(super) fn normalize(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > MAX_AVATAR_BYTES {
        return Err("Choose a smaller image.".into());
    }
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| e.to_string())?;
    if !matches!(
        reader.format(),
        Some(image::ImageFormat::Jpeg | image::ImageFormat::Png)
    ) {
        return Err("Choose a JPEG or PNG image.".into());
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(512);
    limits.max_image_height = Some(512);
    limits.max_alloc = Some(8 * 1024 * 1024);
    reader.limits(limits);
    let photo = reader
        .decode()
        .map_err(|e| match e {
            image::ImageError::Limits(_) => "This image is too large.".to_owned(),
            _ => "This image cannot be read.".to_owned(),
        })?
        .resize_to_fill(256, 256, image::imageops::FilterType::Triangle)
        .to_rgb8();
    for quality in [85, 75, 60, 40] {
        let mut out = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality)
            .encode_image(&photo)
            .map_err(|e| e.to_string())?;
        if out.len() <= MAX_AVATAR_BYTES {
            return Ok(out);
        }
    }
    Err("Choose a less detailed photo.".into())
}

/// Why a photo request failed, with the error code the device gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PhotoError {
    /// Not the host's person, or a device no longer paired.
    NotAllowed(String),
    /// No such agent for this person.
    UnknownAgent(String),
    /// The upload is not an image the host takes.
    Invalid(String),
    /// Another device changed the photo since the revision the edit names.
    Conflict(String),
    /// The bridge's database failed.
    Internal(String),
}

impl PhotoError {
    pub(super) fn code(&self) -> ErrorCode {
        match self {
            PhotoError::NotAllowed(_) => ErrorCode::NotAllowed,
            PhotoError::UnknownAgent(_) => ErrorCode::UnknownAgent,
            PhotoError::Invalid(_) => ErrorCode::BadMessage,
            PhotoError::Conflict(_) => ErrorCode::Conflict,
            PhotoError::Internal(_) => ErrorCode::Internal,
        }
    }
    pub(super) fn message(&self) -> &str {
        match self {
            PhotoError::NotAllowed(m)
            | PhotoError::UnknownAgent(m)
            | PhotoError::Invalid(m)
            | PhotoError::Conflict(m)
            | PhotoError::Internal(m) => m,
        }
    }
    fn into_error(self, of: MessageId) -> ToDevice {
        ToDevice::Error(ErrorBody {
            of: Some(of),
            code: self.code(),
            message: self.message().to_owned(),
        })
    }
}

/// A storage failure: the database's own words go to the host's log, and
/// the device, a guest's included, gets a fixed message.
fn internal(e: impl std::fmt::Display) -> PhotoError {
    eprintln!("enclos app: an agent photo request failed: {e}");
    PhotoError::Internal("The agent photo could not be read or saved. Try again later.".into())
}

fn photo_message(agent: &str, photo: StoredAvatar, of: String) -> ToDevice {
    ToDevice::AgentAvatar(AgentAvatar {
        agent: agent.into(),
        revision: photo.revision,
        version: photo.version,
        image: photo.image.map(|b| encode(&b)),
        of,
    })
}

impl Hub {
    /// Whether `person` is shown `agent`: the one rule `agents.list`, a
    /// photo's reading and its broadcast share. Every paired person sees
    /// every listed agent until sharing (ADR 0043, proposed) narrows it.
    pub(super) fn sees_agent(&self, _person: &str, agent: &str) -> bool {
        self.agents.iter().any(|a| a.name == agent)
    }

    /// The agents `person` is shown, as `agents.list` sends them.
    pub(super) fn agent_infos(
        &self,
        store: &Store,
        person: &str,
    ) -> Result<Vec<AgentInfo>, String> {
        let photos = store.avatar_metadata().map_err(|e| e.to_string())?;
        let plugins = self.plugins.lock().expect("not poisoned");
        Ok(self
            .agents
            .iter()
            .filter(|a| self.sees_agent(person, &a.name))
            .map(|a| AgentInfo {
                avatar: photos.get(&a.name).cloned().unwrap_or_default(),
                can_edit_avatar: self.host.as_deref() == Some(person),
                agent: a.name.clone(),
                runtime: a.runtime.clone(),
                capabilities: plugins
                    .get(&a.name)
                    .map(|p| p.capabilities.clone())
                    .unwrap_or_default(),
                abilities: vec!["read".to_owned(), "chat".to_owned()],
            })
            .collect())
    }

    pub(super) fn avatar_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        write: bool,
    ) -> Result<(), PhotoError> {
        if !store
            .devices()
            .map_err(internal)?
            .iter()
            .any(|d| d.id == device.id && d.person == person)
        {
            return Err(PhotoError::NotAllowed(
                "This device is no longer paired.".into(),
            ));
        }
        if !self.sees_agent(person, agent) {
            return Err(PhotoError::UnknownAgent(
                "This agent is no longer listed by its host.".into(),
            ));
        }
        if write && self.host.as_deref() != Some(person) {
            return Err(PhotoError::NotAllowed(
                "Only the host's person can change a shared agent photo.".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn get_avatar(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        of: String,
    ) -> Result<ToDevice, PhotoError> {
        self.avatar_authority(store, device, person, agent, false)?;
        Ok(photo_message(
            agent,
            store.avatar(agent).map_err(internal)?,
            of,
        ))
    }

    pub(super) fn set_agent_avatar(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        edit: &AvatarSet,
        of: String,
    ) -> Result<ToDevice, PhotoError> {
        let agent = edit.agent.as_str();
        self.avatar_authority(store, device, person, agent, true)?;
        let normalized = if let Some(data) = edit.image.as_deref() {
            if data.len() > MAX_AVATAR_BYTES.div_ceil(3) * 4 {
                return Err(PhotoError::Invalid("Choose a smaller image.".into()));
            }
            let raw = decode("image", data)
                .map_err(|_| PhotoError::Invalid("The image data is not valid.".into()))?;
            Some(normalize(&raw).map_err(PhotoError::Invalid)?)
        } else {
            None
        };
        let Some(saved) = store
            .set_avatar(
                agent,
                edit.revision,
                normalized.as_deref(),
                (&device.id, person),
            )
            .map_err(internal)?
        else {
            return Err(PhotoError::Conflict(
                "The photo changed on another device. Refresh the agent page and try again.".into(),
            ));
        };
        // Every other paired device shown the agent; the device that asked
        // gets the reply instead. Per-agent revisions let devices ignore a
        // delayed broadcast from a concurrent update.
        let paired = store.devices().map_err(internal)?;
        let message = photo_message(agent, saved.clone(), String::new());
        let devices = self.devices.lock().expect("not poisoned");
        for (id, (person, sender, _)) in devices.iter() {
            if id != &device.id
                && self.sees_agent(person, agent)
                && paired.iter().any(|d| &d.id == id && &d.person == person)
            {
                let _ = sender.send(message.clone());
            }
        }
        Ok(photo_message(agent, saved, of))
    }

    /// What answers `agent.avatar.set`, in order: the saved photo; or, when
    /// it failed and the person may still read it, the current photo then
    /// the error, so the device redraws what the host has.
    pub(super) fn avatar_set_replies(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        edit: &AvatarSet,
        id: MessageId,
    ) -> Vec<ToDevice> {
        match self.set_agent_avatar(store, device, person, edit, id.to_string()) {
            Ok(photo) => vec![photo],
            Err(e) => {
                let mut replies = Vec::new();
                if let Ok(current) =
                    self.get_avatar(store, device, person, &edit.agent, String::new())
                {
                    replies.push(current);
                }
                replies.push(e.into_error(id));
                replies
            }
        }
    }

    /// What answers `agent.avatar.get`: the photo, or the error.
    pub(super) fn avatar_get_reply(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        id: MessageId,
    ) -> ToDevice {
        self.get_avatar(store, device, person, agent, id.to_string())
            .unwrap_or_else(|e| e.into_error(id))
    }
}
