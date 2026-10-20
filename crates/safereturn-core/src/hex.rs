//! Minimal hex codec for metadata fields (keys, salts, nonces, ids).
//! Hex is used instead of base64 in JSON metadata and the recovery-key
//! file: it needs no extra dependency, has exactly one canonical form,
//! and a human can compare or retype it without ambiguity.

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode hex, ignoring ASCII whitespace (so grouped key files parse).
/// Returns None on odd length or non-hex characters.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for pair in clean.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_whitespace() {
        let data = [0x00u8, 0xde, 0xad, 0xbe, 0xef, 0xff];
        let text = encode(&data);
        assert_eq!(text, "00deadbeefff");
        assert_eq!(decode(&text).unwrap(), data);
        assert_eq!(decode("00de adbe efff").unwrap(), data);
        assert_eq!(decode("00DEADBEEFFF").unwrap(), data);
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
    }
}
