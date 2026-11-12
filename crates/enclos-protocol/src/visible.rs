//! Text an agent or a person wrote, checked before another person reads it.
//!
//! A control character, a bidirectional override or isolate, a zero-width
//! or other default-ignorable character, a line separator or a blank
//! filler changes how the text around it reads without showing itself:
//! `"\u{202E}niam"` reads as "main", and a command can hide its tail.
//! Names, labels and file names refuse them; a command, which must be
//! shown exactly as it runs, shows them instead ([`revealed`]).
//!
//! The joiners U+200C and U+200D and the emoji variation selectors U+FE0E
//! and U+FE0F are part of ordinary text (Persian spelling, joined emoji),
//! so they count as hidden only where they cannot be: next to ASCII, at an
//! end, or beside another hidden character. The same rule as the app's
//! `Visible` and the Hermes plugin's `visible` module.

/// Whether `c` is one of the joiners that ordinary text uses between two
/// non-ASCII characters: U+200C, U+200D, U+FE0E, U+FE0F.
pub fn is_joiner(c: char) -> bool {
    matches!(c, '\u{200C}' | '\u{200D}' | '\u{FE0E}' | '\u{FE0F}')
}

/// Whether `c` changes how the text around it is shown without being seen,
/// wherever it stands: a control character, a bidirectional mark,
/// embedding, override or isolate, a default-ignorable character (zero
/// width, soft hyphen, tags, variation selectors), a line or paragraph
/// separator, or a blank filler. A joiner ([`is_joiner`]) counts too: a
/// caller that looks at one character at a time cannot tell where it
/// stands, so it refuses it; [`has_hidden`], [`stripped`] and [`revealed`]
/// look at its neighbours.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || is_joiner(c)
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0D}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// For each character of `text`, whether it is hidden where it stands: as
/// [`is_hidden`] says, except that a joiner between two non-ASCII
/// characters that are not hidden themselves (a variation selector: after
/// one) is ordinary text.
fn hidden_marks(text: &str) -> Vec<(char, bool)> {
    let chars: Vec<char> = text.chars().collect();
    let plain = |i: Option<usize>| {
        i.and_then(|i| chars.get(i))
            .is_some_and(|&c| !c.is_ascii() && !is_hidden(c))
    };
    chars
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            let hidden = if is_joiner(c) {
                let before = plain(i.checked_sub(1));
                let after = plain(Some(i + 1));
                match c {
                    '\u{FE0E}' | '\u{FE0F}' => !before,
                    _ => !(before && after),
                }
            } else {
                is_hidden(c)
            };
            (c, hidden)
        })
        .collect()
}

/// Whether `text` holds a character hidden where it stands, newlines
/// aside when `lines` is true.
pub fn has_hidden(text: &str, lines: bool) -> bool {
    hidden_marks(text)
        .iter()
        .any(|&(c, hidden)| hidden && !(lines && c == '\n'))
}

/// `text` without the characters hidden where they stand, newlines kept
/// when `lines` is true: for showing a name or a label that was not
/// checked when it was written.
pub fn stripped(text: &str, lines: bool) -> String {
    hidden_marks(text)
        .into_iter()
        .filter(|&(c, hidden)| !hidden || (lines && c == '\n'))
        .map(|(c, _)| c)
        .collect()
}

/// `text` with each character hidden where it stands, other than a
/// newline, written out as `⟨U+XXXX⟩`, and each tab as `⟨tab⟩`, so that
/// what is shown is what runs.
pub fn revealed(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (c, hidden) in hidden_marks(text) {
        match c {
            '\n' => out.push('\n'),
            '\t' => out.push_str("⟨tab⟩"),
            c if hidden => out.push_str(&format!("⟨U+{:04X}⟩", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `text` without joiners, for telling whether two names read the same:
/// "main" followed by U+FE0F is the name "main".
pub fn bare(text: &str) -> String {
    text.chars().filter(|&c| !is_joiner(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_characters_are_named() {
        for c in [
            '\u{202E}',
            '\u{2066}',
            '\u{200B}',
            '\u{200E}',
            '\u{FEFF}',
            '\u{061C}',
            '\u{0007}',
            '\u{0085}',
            '\u{00AD}',
            '\u{034F}',
            '\u{115F}',
            '\u{3164}',
            '\u{FFA0}',
            '\u{2800}',
            '\u{2028}',
            '\u{2029}',
            '\u{206A}',
            '\u{FFF9}',
            '\u{FE00}',
            '\u{E0041}',
            '\u{E007F}',
            '\u{E0100}',
            '\u{200D}',
        ] {
            assert!(is_hidden(c), "{:04X}", c as u32);
            assert!(has_hidden(&format!("a{c}b"), true), "{:04X}", c as u32);
        }
        for c in ['a', 'é', 'ß', '中', '😀', ' ', '-', 'ی'] {
            assert!(!is_hidden(c), "{c}");
        }
    }

    #[test]
    fn joiners_are_text_between_non_ascii_characters_only() {
        // A joined emoji, a Persian word, an emoji with its presentation selector.
        for text in [
            "\u{1F469}\u{200D}\u{1F4BB}",
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
            "\u{2764}\u{FE0F}",
        ] {
            assert!(!has_hidden(text, false), "{text}");
            assert_eq!(stripped(text, false), text);
            assert_eq!(revealed(text), text);
        }
        // Next to ASCII, at an end, or beside a hidden character.
        for text in [
            "ma\u{200D}in",
            "main\u{FE0F}",
            "\u{200D}\u{1F4BB}",
            "\u{1F469}\u{200D}",
            "\u{1F469}\u{200D}\u{202E}",
        ] {
            assert!(has_hidden(text, false), "{text:?}");
        }
        assert_eq!(stripped("main\u{FE0F}", false), "main");
        assert_eq!(revealed("ma\u{200D}in"), "ma⟨U+200D⟩in");
    }

    #[test]
    fn newlines_count_only_when_lines_are_refused() {
        assert!(has_hidden("a\nb", false));
        assert!(!has_hidden("a\nb", true));
        assert!(has_hidden("a\u{202E}b", true));
        assert!(!has_hidden("main", false));
        assert_eq!(stripped("a\nb\u{202E}", true), "a\nb");
        assert_eq!(stripped("a\nb", false), "ab");
    }

    #[test]
    fn revealed_shows_what_runs() {
        assert_eq!(
            revealed("ls\u{202E} -la\tx\ny\u{E0041}"),
            "ls⟨U+202E⟩ -la⟨tab⟩x\ny⟨U+E0041⟩"
        );
        assert_eq!(revealed("echo ok"), "echo ok");
    }

    #[test]
    fn bare_names_compare_without_joiners() {
        assert_eq!(bare("main\u{FE0F}"), "main");
        assert_eq!(bare("\u{1F469}\u{200D}\u{1F4BB}"), "\u{1F469}\u{1F4BB}");
    }
}
