//! A versioned agent export: bounded Enclos metadata, then an opaque runtime export.
//! The host never extracts the runtime's archive.
use std::io::{self, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{agent::AgentName, runtime::RuntimeKind, sandbox::SandboxName};

const MAGIC: &[u8] = b"ENCLOS_AGENT_EXPORT_V1\n";
const MAX_HEADER: usize = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub display_name: Option<String>,
    /// Base64url JPEG or PNG; bounded like the mobile app's shared image.
    pub avatar: Option<String>,
}

impl Presentation {
    pub fn image(&self) -> io::Result<Option<Vec<u8>>> {
        self.avatar
            .as_ref()
            .map(|text| {
                if text.len() > enclos_protocol::avatar::MAX_AVATAR_BYTES.div_ceil(3) * 4 {
                    return Err(invalid("the agent image is too large"));
                }
                let bytes = enclos_protocol::pairing::decode("avatar", text).map_err(invalid)?;
                if bytes.is_empty() || bytes.len() > enclos_protocol::avatar::MAX_AVATAR_BYTES {
                    return Err(invalid("the agent image is empty or too large"));
                }
                let mut reader = image::ImageReader::new(io::Cursor::new(&bytes))
                    .with_guessed_format()
                    .map_err(invalid)?;
                if !matches!(
                    reader.format(),
                    Some(image::ImageFormat::Jpeg | image::ImageFormat::Png)
                ) {
                    return Err(invalid("the agent image must be JPEG or PNG"));
                }
                let mut limits = image::Limits::default();
                limits.max_image_width = Some(512);
                limits.max_image_height = Some(512);
                limits.max_alloc = Some(8 * 1024 * 1024);
                reader.limits(limits);
                reader.decode().map_err(invalid)?;
                Ok(bytes)
            })
            .transpose()
    }

    pub fn validate(&self) -> io::Result<()> {
        let normalized = enclos_protocol::agent_name::normalize(self.display_name.as_deref())
            .map_err(invalid)?;
        if normalized != self.display_name {
            return Err(invalid("the display name is not normalized"));
        }
        self.image()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub runtime: String,
    pub source_agent: String,
    pub presentation: Presentation,
    pub payload_bytes: u64,
    pub payload_sha256: String,
}

impl Manifest {
    fn validate(&self) -> io::Result<()> {
        if self.schema_version != 1 {
            return Err(invalid("unsupported agent export version"));
        }
        self.runtime.parse::<RuntimeKind>().map_err(invalid)?;
        let (sandbox, agent) = self
            .source_agent
            .split_once('/')
            .ok_or_else(|| invalid("invalid source agent"))?;
        sandbox.parse::<SandboxName>().map_err(invalid)?;
        agent.parse::<AgentName>().map_err(invalid)?;
        if self.payload_bytes == 0
            || self.payload_sha256.len() != 64
            || !self
                .payload_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid runtime export size or checksum"));
        }
        self.presentation.validate()
    }
}

/// Streams and hashes the runtime's export twice so a changed source is refused.
pub fn write(
    payload: &mut (impl Read + Seek),
    output: &mut impl Write,
    runtime: RuntimeKind,
    source_agent: String,
    presentation: Presentation,
) -> io::Result<Manifest> {
    payload.seek(SeekFrom::Start(0))?;
    let (payload_bytes, payload_sha256) = copy(payload, &mut io::sink())?;
    let manifest = Manifest {
        schema_version: 1,
        runtime: runtime.to_string(),
        source_agent,
        presentation,
        payload_bytes,
        payload_sha256,
    };
    manifest.validate()?;
    let header = serde_json::to_vec(&manifest).map_err(invalid)?;
    if header.len() > MAX_HEADER {
        return Err(invalid("agent export metadata is too large"));
    }
    output.write_all(MAGIC)?;
    output.write_all(&(header.len() as u32).to_be_bytes())?;
    output.write_all(&header)?;
    payload.seek(SeekFrom::Start(0))?;
    let (size, digest) = copy(payload, output)?;
    if size != manifest.payload_bytes || digest != manifest.payload_sha256 {
        return Err(invalid("the runtime export changed while it was copied"));
    }
    Ok(manifest)
}

/// Validates metadata and streams the opaque payload; refuses truncation, changes and trailing bytes.
pub fn read(input: &mut impl Read, payload: &mut impl Write) -> io::Result<Manifest> {
    let mut magic = vec![0; MAGIC.len()];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(invalid(
            "not a supported Enclos agent export; use agent add --from for a runtime export",
        ));
    }
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HEADER {
        return Err(invalid("invalid agent export metadata length"));
    }
    let mut header = vec![0; length];
    input.read_exact(&mut header)?;
    let manifest: Manifest = serde_json::from_slice(&header).map_err(invalid)?;
    manifest.validate()?;
    let (size, digest) = copy(&mut input.take(manifest.payload_bytes), payload)?;
    if size != manifest.payload_bytes || digest != manifest.payload_sha256 {
        return Err(invalid(
            "runtime export is truncated or its checksum does not match",
        ));
    }
    let mut extra = [0];
    if input.read(&mut extra)? != 0 {
        return Err(invalid("unexpected bytes after the runtime export"));
    }
    Ok(manifest)
}

fn copy(input: &mut impl Read, output: &mut impl Write) -> io::Result<(u64, String)> {
    let mut sha = Sha256::new();
    let mut bytes = 0;
    let mut buf = [0; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
        sha.update(&buf[..n]);
        bytes += n as u64;
    }
    Ok((
        bytes,
        sha.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn photo() -> Vec<u8> {
        let mut out = io::Cursor::new(Vec::new());
        image::RgbImage::new(2, 2)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }
    fn exported() -> (Vec<u8>, Manifest) {
        let mut out = Vec::new();
        let manifest = write(
            &mut io::Cursor::new(vec![42; 200_000]),
            &mut out,
            RuntimeKind::Hermes,
            "pi/comptoir-dev".into(),
            Presentation {
                display_name: Some("Gégé Commit".into()),
                avatar: Some(enclos_protocol::pairing::encode(&photo())),
            },
        )
        .unwrap();
        (out, manifest)
    }
    #[test]
    fn name_image_and_opaque_runtime_data_round_trip() {
        let (bytes, manifest) = exported();
        let mut payload = Vec::new();
        assert_eq!(read(&mut bytes.as_slice(), &mut payload).unwrap(), manifest);
        assert_eq!(payload, vec![42; 200_000]);
        assert_eq!(manifest.presentation.image().unwrap().unwrap(), photo());
    }
    #[test]
    fn changed_truncated_and_appended_runtime_exports_are_refused() {
        let (bytes, _) = exported();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        let mut appended = bytes.clone();
        appended.push(0);
        for input in [&changed[..], &bytes[..bytes.len() - 1], &appended[..]] {
            assert!(read(&mut &input[..], &mut io::sink()).is_err());
        }
    }
    #[test]
    fn huge_headers_unknown_versions_and_raw_archives_are_refused() {
        let mut huge = MAGIC.to_vec();
        huge.extend(u32::MAX.to_be_bytes());
        for input in [huge, b"not an enclos export".to_vec()] {
            assert!(read(&mut input.as_slice(), &mut io::sink()).is_err());
        }
        let (_, mut m) = exported();
        m.schema_version = 2;
        assert!(m.validate().is_err());
        m.schema_version = 1;
        m.source_agent = "../comptoir-dev".into();
        assert!(m.validate().is_err());
    }
    #[test]
    fn invalid_names_and_non_images_never_reach_import() {
        for p in [
            Presentation {
                display_name: Some("bad\nname".into()),
                avatar: None,
            },
            Presentation {
                display_name: None,
                avatar: Some(enclos_protocol::pairing::encode(b"not a photo")),
            },
        ] {
            assert!(p.validate().is_err());
        }
    }
}
