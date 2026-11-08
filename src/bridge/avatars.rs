//! Host-owned agent photos: decode a bounded raster, normalize it, then publish a versioned asset.
use super::super::store::StoredAvatar;
use super::*;
use enclos_protocol::avatar::{AgentAvatar, MAX_AVATAR_BYTES};

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
        .map_err(|_| "This image cannot be read or is too large.".to_owned())?
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
    pub(super) fn avatar_authority(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        agent: &str,
        write: bool,
    ) -> Result<(), String> {
        if !store
            .devices()
            .map_err(|e| e.to_string())?
            .iter()
            .any(|d| d.id == device.id && d.person == person)
        {
            return Err("This device is no longer paired.".into());
        }
        if !self.agents.iter().any(|a| a.name == agent) {
            return Err("This agent is no longer listed by its host.".into());
        }
        if write && self.host.as_deref() != Some(person) {
            return Err("Only the host's person can change a shared agent photo.".into());
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
    ) -> Result<ToDevice, String> {
        self.avatar_authority(store, device, person, agent, false)?;
        Ok(photo_message(
            agent,
            store.avatar(agent).map_err(|e| e.to_string())?,
            of,
        ))
    }
    pub(super) fn set_agent_avatar(
        &self,
        store: &Store,
        device: &Device,
        person: &str,
        edit: &enclos_protocol::avatar::AvatarSet,
        of: String,
    ) -> Result<ToDevice, String> {
        let agent = edit.agent.as_str();
        self.avatar_authority(store, device, person, agent, true)?;
        let normalized = if let Some(data) = edit.image.as_deref() {
            if data.len() > MAX_AVATAR_BYTES.div_ceil(3) * 4 {
                return Err("Choose a smaller image.".into());
            }
            let raw =
                decode("image", data).map_err(|_| "The image data is not valid.".to_owned())?;
            Some(normalize(&raw)?)
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
            .map_err(|e| e.to_string())?
        else {
            return Err(
                "The photo changed on another device. Refresh the agent page and try again.".into(),
            );
        };
        // Per-agent revisions let devices ignore a delayed broadcast from a concurrent update.
        let paired = store.devices().map_err(|e| e.to_string())?;
        let message = photo_message(agent, saved.clone(), String::new());
        let devices = self.devices.lock().expect("not poisoned");
        for (id, (person, sender)) in devices.iter() {
            if paired.iter().any(|d| &d.id == id && &d.person == person) {
                let _ = sender.send(message.clone());
            }
        }
        Ok(photo_message(agent, saved, of))
    }
}
