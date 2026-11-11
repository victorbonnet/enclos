//! Text an agent or a person wrote, checked before another person reads it.
//!
//! A control character, a bidirectional override or isolate, or a
//! zero-width character changes how the text around it reads without
//! showing itself: `"\u{202E}niam"` reads as "main", and a command can hide
//! its tail. Names, labels and file names refuse them; a command, which
//! must be shown exactly as it runs, shows them instead ([`revealed`]).

/// Whether `c` changes how the text around it is shown without being
/// seen: a control character, a bidirectional mark, embedding, override
/// or isolate, a zero-width character, or a soft hyphen.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Whether `text` holds a character [`is_hidden`] names, newlines aside
/// when `lines` is true.
pub fn has_hidden(text: &str, lines: bool) -> bool {
    text.chars().any(|c| is_hidden(c) && !(lines && c == '\n'))
}

/// `text` with each hidden character other than a newline written out as
/// `⟨U+XXXX⟩`, and each tab as `⟨tab⟩`, so that what is shown is what runs.
pub fn revealed(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("⟨tab⟩"),
            c if is_hidden(c) => out.push_str(&format!("⟨U+{:04X}⟩", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_named() {
        for c in [
            '\u{202E}', '\u{2066}', '\u{200B}', '\u{200D}', '\u{FEFF}', '\u{061C}', '\u{0007}',
            '\u{00AD}',
        ] {
            assert!(is_hidden(c), "{:04X}", c as u32);
        }
        for c in ['a', 'é', 'ß', '中', '😀', ' ', '-'] {
            assert!(!is_hidden(c), "{c}");
        }
    }

    #[test]
    fn newlines_count_only_when_lines_are_refused() {
        assert!(has_hidden("a\nb", false));
        assert!(!has_hidden("a\nb", true));
        assert!(has_hidden("a\u{202E}b", true));
        assert!(!has_hidden("main", false));
    }

    #[test]
    fn revealed_shows_what_runs() {
        assert_eq!(revealed("ls\u{202E} -la\tx\ny"), "ls⟨U+202E⟩ -la⟨tab⟩x\ny");
        assert_eq!(revealed("echo ok"), "echo ok");
    }
}
