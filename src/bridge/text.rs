//! Text a caller chose, made safe to store and show at a terminal: a
//! device's name in `pair.request`, a node's name from the transport.

/// Characters that move the cursor, hide what follows or reorder it:
/// controls, and the invisible and bidirectional formatting characters.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{61c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}

/// `text` without hidden characters, its runs of white space made one
/// space, cut to `max` characters; `fallback` when nothing is left.
pub fn plain(text: &str, max: usize, fallback: &str) -> String {
    let shown: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !hidden(*c))
        .collect();
    let words: Vec<&str> = shown.split(' ').filter(|w| !w.is_empty()).collect();
    let joined: String = words.join(" ").chars().take(max).collect();
    match joined.trim_end() {
        "" => fallback.to_owned(),
        kept => kept.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_cannot_redraw_the_terminal_or_hide_what_follows() {
        assert_eq!(plain("Pixel 9", 64, "?"), "Pixel 9");
        // A carriage return and an escape that would redraw the prompt
        assert_eq!(
            plain("Pixel\r\x1b[2KAccept? [y/N] ", 64, "?"),
            "Pixel [2KAccept? [y/N]"
        );
        // Right-to-left override and zero-width space go; a line separator is
        // white space
        assert_eq!(
            plain("evil\u{202e}gnp.exe\u{200b}\u{2028}x", 64, "?"),
            "evilgnp.exe x"
        );
        assert_eq!(plain(&"é".repeat(100), 64, "?").chars().count(), 64);
        assert_eq!(plain("\u{202e}\n\t ", 64, "unnamed"), "unnamed");
    }
}
