//! Files a person sends an agent with a message (#298, ADR 0076, proposed):
//! what `message.begin` declares and what `message.part` carries, on the
//! device leg and again on the plugin leg (`docs/protocol.md`, Sending
//! files). Each message is checked here on its own; whether a part is the
//! next one of the message being sent is the receiver's check.

use serde::{Deserialize, Serialize};

use crate::ids::MessageId;

/// The most files of one message.
pub const MAX_FILES: usize = 4;
/// The largest file, in bytes.
pub const MAX_FILE_BYTES: u64 = 10_000_000;
/// The most bytes one part carries: as `attachment.data`, its base64 fits a
/// Noise message.
pub const MAX_PART_BYTES: usize = crate::device::ATTACHMENT_CHUNK;
/// The most characters of a file's name, as an agent's files' rule.
pub const MAX_NAME_CHARS: usize = 120;
/// The most bytes of a file's name.
pub const MAX_NAME_BYTES: usize = 255;

/// Every file an agent takes: extension (any case), the one media type it
/// is sent as, and whether it is a photo. Documents are those Hermes takes
/// (`SUPPORTED_DOCUMENT_TYPES`); `.py` and `.sh` are text, never run.
/// Photos are JPEG, PNG, WebP and GIF (a phone converts HEIC to JPEG). No
/// HTML, SVG, audio, video or executable.
pub const FILE_TYPES: &[(&str, &str, bool)] = &[
    (".jpg", "image/jpeg", true),
    (".jpeg", "image/jpeg", true),
    (".png", "image/png", true),
    (".webp", "image/webp", true),
    (".gif", "image/gif", true),
    (".pdf", "application/pdf", false),
    (".md", "text/markdown", false),
    (".txt", "text/plain", false),
    (".csv", "text/csv", false),
    (".log", "text/plain", false),
    (".json", "application/json", false),
    (".xml", "application/xml", false),
    (".yaml", "application/yaml", false),
    (".yml", "application/yaml", false),
    (".toml", "application/toml", false),
    (".py", "text/plain", false),
    (".sh", "text/plain", false),
    (".zip", "application/zip", false),
    (".doc", "application/msword", false),
    (".xls", "application/vnd.ms-excel", false),
    (".ppt", "application/vnd.ms-powerpoint", false),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        false,
    ),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        false,
    ),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        false,
    ),
];

/// Why a file or a part was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IncomingError {
    #[error("a file holds 1 to 10,000,000 bytes")]
    Size,
    #[error("a file's type is not one an agent takes, or its name's extension is not its type's")]
    Type,
    #[error("a file's name is one visible component of at most 120 characters, not `.` or `..`")]
    Name,
    #[error("a message carries 1 to 4 files")]
    Count,
    #[error("a part holds 1 to 45,000 bytes, as unpadded base64url")]
    Part,
}

/// A file's name, which is only ever shown: one component (no `/` or `\`),
/// not `.` or `..`, no control, line break, bidirectional or zero-width
/// character ([`crate::visible`]), no space at either end, at most
/// [`MAX_NAME_CHARS`] and [`MAX_NAME_BYTES`]. Refused rather than changed.
pub fn check_name(name: &str) -> Result<(), IncomingError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_NAME_BYTES
        || name.chars().count() > MAX_NAME_CHARS
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
        || crate::visible::has_hidden(name, false)
        || name.trim() != name
    {
        return Err(IncomingError::Name);
    }
    Ok(())
}

/// Whether a file of type `mime` named `name` is a photo: its extension
/// (after the last dot, with something before it) must be in
/// [`FILE_TYPES`] with exactly `mime`. Declared, not proven.
pub fn is_photo(mime: &str, name: &str) -> Result<bool, IncomingError> {
    let dot = name
        .rfind('.')
        .filter(|&at| at > 0)
        .ok_or(IncomingError::Type)?;
    FILE_TYPES
        .iter()
        .find(|(ext, typed, _)| ext.eq_ignore_ascii_case(&name[dot..]) && *typed == mime)
        .map(|(_, _, photo)| *photo)
        .ok_or(IncomingError::Type)
}

/// One file a message carries, declared before its bytes: its name, media
/// type and exact size, checked together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawFile")]
pub struct IncomingFile {
    pub name: String,
    pub mime: String,
    pub size: u64,
}

#[derive(Deserialize)]
struct RawFile {
    name: String,
    mime: String,
    size: u64,
}

impl TryFrom<RawFile> for IncomingFile {
    type Error = IncomingError;

    fn try_from(raw: RawFile) -> Result<Self, IncomingError> {
        IncomingFile::new(raw.name, raw.mime, raw.size)
    }
}

impl IncomingFile {
    pub fn new(name: String, mime: String, size: u64) -> Result<Self, IncomingError> {
        check_name(&name)?;
        is_photo(&mime, &name)?;
        if size == 0 || size > MAX_FILE_BYTES {
            return Err(IncomingError::Size);
        }
        Ok(Self { name, mime, size })
    }
}

/// A message with files from a device (`message.begin`): its text and the
/// files whose bytes follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Begin {
    pub conversation: crate::ids::ConversationId,
    pub text: String,
    #[serde(deserialize_with = "files")]
    pub files: Vec<IncomingFile>,
}

/// A message's files: 1 to [`MAX_FILES`].
pub fn files<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IncomingFile>, D::Error> {
    let files = Vec::<IncomingFile>::deserialize(d)?;
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(serde::de::Error::custom(IncomingError::Count));
    }
    Ok(files)
}

/// A `message.in`'s files: none, or 1 to [`MAX_FILES`].
pub fn some_files<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IncomingFile>, D::Error> {
    let files = Vec::<IncomingFile>::deserialize(d)?;
    if files.len() > MAX_FILES {
        return Err(serde::de::Error::custom(IncomingError::Count));
    }
    Ok(files)
}

/// One part of a file of the message being sent (`message.part`): its
/// bytes at `offset` in file number `file` (from 0) of message `message`,
/// the `message.begin`'s (device leg) or `message.in`'s (plugin leg) id.
/// Parts come in order, every byte once: the receiver refuses the whole
/// message at the first part that is not the next one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub message: MessageId,
    pub file: u8,
    pub offset: u64,
    pub data: PartData,
}

/// A part's bytes, 1 to [`MAX_PART_BYTES`], as unpadded base64url; its
/// length is checked before it is decoded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PartData(Vec<u8>);

impl PartData {
    pub fn new(bytes: Vec<u8>) -> Result<Self, IncomingError> {
        if bytes.is_empty() || bytes.len() > MAX_PART_BYTES {
            return Err(IncomingError::Part);
        }
        Ok(Self(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for PartData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A file's bytes stay out of logs.
        write!(f, "PartData({} bytes)", self.0.len())
    }
}

impl TryFrom<String> for PartData {
    type Error = IncomingError;

    fn try_from(data: String) -> Result<Self, IncomingError> {
        use base64::Engine as _;
        if data.is_empty() || data.len() > MAX_PART_BYTES.div_ceil(3) * 4 {
            return Err(IncomingError::Part);
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data.as_bytes())
            .map_err(|_| IncomingError::Part)?;
        Self::new(bytes)
    }
}

impl From<PartData> for String {
    fn from(data: PartData) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, mime: &str, size: u64) -> Result<IncomingFile, IncomingError> {
        IncomingFile::new(name.into(), mime.into(), size)
    }

    #[test]
    fn a_file_is_checked_by_its_name_type_and_size() {
        assert!(file("Photo.JPG", "image/jpeg", 1).is_ok());
        assert!(file("report.pdf", "application/pdf", MAX_FILE_BYTES).is_ok());
        let pdf = "application/pdf";
        for (name, mime, size, error) in [
            ("a.pdf", pdf, MAX_FILE_BYTES + 1, IncomingError::Size),
            ("a.pdf", pdf, 0, IncomingError::Size),
            ("../a.pdf", pdf, 1, IncomingError::Name),
            ("a/b.pdf", pdf, 1, IncomingError::Name),
            ("a\\b.pdf", pdf, 1, IncomingError::Name),
            ("..", pdf, 1, IncomingError::Name),
            (" a.pdf", pdf, 1, IncomingError::Name),
            ("a\u{202e}.pdf", pdf, 1, IncomingError::Name),
            ("a.pdf", "image/png", 1, IncomingError::Type),
            ("page.html", "text/html", 1, IncomingError::Type),
            (".png", "image/png", 1, IncomingError::Type),
            ("noext", "text/plain", 1, IncomingError::Type),
        ] {
            assert_eq!(file(name, mime, size), Err(error), "{name}");
        }
        assert!(is_photo("image/png", "x.png").unwrap());
        assert!(!is_photo("text/plain", "x.txt").unwrap());
    }

    #[test]
    fn a_part_holds_at_most_one_chunk_of_canonical_base64url() {
        use base64::Engine as _;
        let encode = |n: usize| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![7; n]);
        assert!(PartData::try_from(encode(MAX_PART_BYTES)).is_ok());
        assert!(PartData::try_from(encode(MAX_PART_BYTES + 1)).is_err());
        assert!(PartData::try_from(String::new()).is_err());
        assert!(PartData::try_from("AA==".to_owned()).is_err());
        assert!(PartData::try_from("A+/B".to_owned()).is_err());
    }
}
