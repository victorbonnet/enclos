//! New ids for messages and conversations: random, as UUIDs are, read from
//! the system's random source.

/// `n` bytes from the system's random source.
pub fn random_bytes(n: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(bytes)
}

/// 16 random bytes in the 8-4-4-4-12 form of a UUID (version 4).
pub fn new_id() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_a_new_version_4_uuid() {
        let a = new_id().unwrap();
        let b = new_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
    }
}
