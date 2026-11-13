//! A versioned agent export: bounded Enclos metadata, then an opaque runtime export.
//! The host never extracts the runtime's archive.
use std::io::{self, Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{agent::AgentName, runtime::RuntimeKind, sandbox::SandboxName};

const MAGIC: &[u8] = b"ENCLOS_AGENT_EXPORT_V1\n";
const MAX_HEADER: usize = 64 * 1024;
const MAX_STATE: u64 = 256 * 1024 * 1024;
/// Maximum compressed runtime data, enforced before reading and while copying.
pub const MAX_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024 * 1024;
use crate::bridge::portable::HostState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSection {
    pub bytes: u64,
    pub sha256: String,
}
fn native_format() -> String {
    "native".into()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub display_name: Option<String>,
    /// Base64url JPEG or PNG; bounded like the mobile app's shared image.
    #[serde(alias = "avatar")]
    pub photo: Option<String>,
}

impl Presentation {
    pub fn image(&self) -> io::Result<Option<Vec<u8>>> {
        self.photo
            .as_ref()
            .map(|text| {
                if text.len() > enclos_protocol::avatar::MAX_AVATAR_BYTES.div_ceil(3) * 4 {
                    return Err(invalid("the agent image is too large"));
                }
                let bytes = enclos_protocol::pairing::decode("photo", text).map_err(invalid)?;
                if bytes.is_empty() || bytes.len() > enclos_protocol::avatar::MAX_AVATAR_BYTES {
                    return Err(invalid("the agent image is empty or too large"));
                }
                crate::bridge::server::normalize_photo(&bytes).map_err(invalid)
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
    #[serde(default = "native_format", skip_serializing_if = "is_native")]
    pub runtime_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateSection>,
}
fn is_native(value: &str) -> bool {
    value == "native"
}

impl Manifest {
    fn validate(&self) -> io::Result<()> {
        if !matches!(self.schema_version, 1 | 2) {
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
            || self.payload_bytes > MAX_PAYLOAD_BYTES
            || self.payload_sha256.len() != 64
            || !self
                .payload_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid runtime export size or checksum"));
        }
        if self.runtime_format.is_empty()
            || self.runtime_format.len() > 64
            || !self
                .runtime_format
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid("invalid runtime data format"));
        }
        if self.schema_version == 1 && (self.state.is_some() || self.runtime_format != "native") {
            return Err(invalid("invalid legacy export"));
        }
        if self.schema_version == 2 && self.state.is_none() {
            return Err(invalid("complete export has no Enclos data"));
        }
        if let Some(s) = &self.state
            && (s.bytes == 0
                || s.bytes > MAX_STATE
                || s.sha256.len() != 64
                || !s
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            return Err(invalid("invalid Enclos data size or checksum"));
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
    write_parts(
        payload,
        output,
        runtime,
        source_agent,
        presentation,
        "native",
        None,
    )
}

/// A complete export carries a separately hashed, bounded host-owned section.
/// This contains credentials: it must never be printed in plans or audit logs.
pub fn write_complete(
    payload: &mut (impl Read + Seek),
    output: &mut impl Write,
    runtime: RuntimeKind,
    source_agent: String,
    presentation: Presentation,
    format: &str,
    state: &HostState,
) -> io::Result<Manifest> {
    state.validate()?;
    let bytes = zeroize::Zeroizing::new(
        serde_json::to_vec(state).map_err(|_| invalid("cannot serialize Enclos data"))?,
    );
    if bytes.len() as u64 > MAX_STATE {
        return Err(invalid(
            "Enclos history and attachments exceed the 256 MiB export limit",
        ));
    }
    write_parts(
        payload,
        output,
        runtime,
        source_agent,
        presentation,
        format,
        Some(&bytes),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_parts(
    payload: &mut (impl Read + Seek),
    output: &mut impl Write,
    runtime: RuntimeKind,
    source_agent: String,
    presentation: Presentation,
    format: &str,
    state: Option<&[u8]>,
) -> io::Result<Manifest> {
    let size = payload.seek(SeekFrom::End(0))?;
    if size == 0 || size > MAX_PAYLOAD_BYTES {
        return Err(invalid(
            "runtime data exceeds the 32 GiB export limit or is empty",
        ));
    }
    payload.seek(SeekFrom::Start(0))?;
    let (payload_bytes, payload_sha256) =
        copy(&mut payload.take(MAX_PAYLOAD_BYTES + 1), &mut io::sink())?;
    if payload_bytes > MAX_PAYLOAD_BYTES {
        return Err(invalid("runtime data exceeds the 32 GiB export limit"));
    }
    let manifest = Manifest {
        schema_version: if state.is_some() { 2 } else { 1 },
        runtime: runtime.to_string(),
        source_agent,
        presentation,
        payload_bytes,
        payload_sha256,
        runtime_format: format.into(),
        state: state.map(|s| StateSection {
            bytes: s.len() as u64,
            sha256: crate::policy::sha256_hex(s),
        }),
    };
    manifest.validate()?;
    let header = serde_json::to_vec(&manifest).map_err(invalid)?;
    if header.len() > MAX_HEADER {
        return Err(invalid("agent export metadata is too large"));
    }
    output.write_all(MAGIC)?;
    output.write_all(&(header.len() as u32).to_be_bytes())?;
    output.write_all(&header)?;
    if let Some(state) = state {
        output.write_all(state)?;
    }
    payload.seek(SeekFrom::Start(0))?;
    let (size, digest) = copy(&mut payload.take(manifest.payload_bytes + 1), output)?;
    if size != manifest.payload_bytes || digest != manifest.payload_sha256 {
        return Err(invalid("the runtime export changed while it was copied"));
    }
    Ok(manifest)
}

/// Validates metadata and streams the opaque payload; refuses truncation, changes and trailing bytes.
pub fn read(input: &mut impl Read, payload: &mut impl Write) -> io::Result<Manifest> {
    read_complete(input, payload).map(|(manifest, _)| manifest)
}

pub fn read_complete(
    input: &mut impl Read,
    payload: &mut impl Write,
) -> io::Result<(Manifest, Option<HostState>)> {
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
    let state = if let Some(section) = &manifest.state {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        input.take(section.bytes).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != section.bytes
            || crate::policy::sha256_hex(&bytes) != section.sha256
        {
            return Err(invalid(
                "Enclos data is truncated or its checksum does not match",
            ));
        }
        let state: HostState =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid Enclos data"))?;
        state.validate()?;
        Some(state)
    } else {
        None
    };
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
    Ok((manifest, state))
}

/// Computes an audit digest during the existing IO pass.
pub(crate) struct Hashed<T> {
    inner: T,
    sha: Sha256,
}
impl<T> Hashed<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            sha: Sha256::new(),
        }
    }
    pub fn sha256(&self) -> String {
        self.sha
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
impl<T: Read> Read for Hashed<T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(bytes)?;
        self.sha.update(&bytes[..n]);
        Ok(n)
    }
}
impl<T: Write> Write for Hashed<T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.sha.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
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
                photo: Some(enclos_protocol::pairing::encode(&photo())),
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
        assert_eq!(
            manifest.presentation.image().unwrap().unwrap(),
            crate::bridge::server::normalize_photo(&photo()).unwrap()
        );
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
                photo: None,
            },
            Presentation {
                display_name: None,
                photo: Some(enclos_protocol::pairing::encode(b"not a photo")),
            },
        ] {
            assert!(p.validate().is_err());
        }
    }
}

#[cfg(test)]
mod complete_tests {
    use super::*;
    #[test]
    fn complete_sections_round_trip_and_tampering_is_refused() {
        let state = HostState {
            credentials: vec![crate::bridge::portable::Credential {
                variable: "API_TOKEN".into(),
                value: crate::model::secret::SecretValue::new("sensitive-token".into()).unwrap(),
            }],
            ..Default::default()
        };
        let mut bytes = Vec::new();
        let manifest = write_complete(
            &mut io::Cursor::new(b"opaque runtime"),
            &mut bytes,
            RuntimeKind::Hermes,
            "old/main".into(),
            Presentation::default(),
            "hermes-data-v1",
            &state,
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 2);
        let mut payload = Vec::new();
        let (_, read) = read_complete(&mut io::Cursor::new(&bytes), &mut payload).unwrap();
        assert_eq!(payload, b"opaque runtime");
        assert_eq!(
            read.unwrap().credentials[0].value.expose(),
            "sensitive-token"
        );
        let index = bytes
            .windows(15)
            .position(|w| w == b"sensitive-token")
            .unwrap();
        bytes[index] ^= 1;
        assert!(read_complete(&mut io::Cursor::new(&bytes), &mut Vec::new()).is_err());
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn review_imported_photos_drop_trailing_metadata_and_use_bridge_dimensions() {
        let mut photo = io::Cursor::new(Vec::new());
        image::RgbImage::new(512, 300)
            .write_to(&mut photo, image::ImageFormat::Png)
            .unwrap();
        let mut bytes = photo.into_inner();
        bytes.extend_from_slice(b"PRIVATE_PHOTO_TRAILER");
        let p = Presentation {
            display_name: None,
            photo: Some(enclos_protocol::pairing::encode(&bytes)),
        };
        let clean = p.image().unwrap().unwrap();
        let image = image::load_from_memory(&clean).unwrap();
        assert_eq!((image.width(), image.height()), (256, 256));
        assert!(clean.starts_with(&[0xff, 0xd8]));
        assert!(!clean.windows(21).any(|w| w == b"PRIVATE_PHOTO_TRAILER"));
    }
    #[test]
    fn review_oversized_payload_is_refused_before_any_read() {
        struct Oversized;
        impl Read for Oversized {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("oversized input must not be read")
            }
        }
        impl Seek for Oversized {
            fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
                Ok(if matches!(seek, SeekFrom::End(_)) {
                    32 * 1024 * 1024 * 1024 + 1
                } else {
                    0
                })
            }
        }
        assert!(
            write(
                &mut Oversized,
                &mut Vec::new(),
                RuntimeKind::Hermes,
                "old/main".into(),
                Presentation::default()
            )
            .is_err()
        );
        let mut out = Vec::new();
        let mut manifest = write(
            &mut io::Cursor::new(b"small"),
            &mut out,
            RuntimeKind::Hermes,
            "old/main".into(),
            Presentation::default(),
        )
        .unwrap();
        manifest.payload_bytes = 32 * 1024 * 1024 * 1024 + 1;
        assert!(manifest.validate().is_err());
    }
}

#[cfg(test)]
mod legacy_photo_tests {
    use super::*;
    #[test]
    fn review_new_exports_use_photo_and_legacy_avatar_is_readable() {
        let photo: Presentation =
            serde_json::from_str(r#"{"display_name":null,"avatar":null}"#).unwrap();
        let json = serde_json::to_value(&photo).unwrap();
        assert!(json.get("photo").is_some());
        assert!(json.get("avatar").is_none());
        assert!(
            serde_json::from_str::<Presentation>(
                r#"{"display_name":null,"avatar":null,"photo":null}"#
            )
            .is_err()
        );
    }
}
