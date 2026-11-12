//! Text a caller chose, made safe to store and show at a terminal: a
//! device's name in `pair.request`, a node's name from the transport.

use enclos_protocol::visible::stripped;

/// `text` without the characters hidden where they stand (the shared rule
/// of [`enclos_protocol::visible`]), its runs of white space made one
/// space, cut to `max` characters; `fallback` when nothing is left.
pub fn plain(text: &str, max: usize, fallback: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let shown = stripped(&spaced, false);
    let words: Vec<&str> = shown.split(' ').filter(|w| !w.is_empty()).collect();
    let cut: String = words.join(" ").chars().take(max).collect();
    // A joiner the cut left at the end is hidden there
    match stripped(&cut, false).trim_end() {
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

    #[test]
    fn a_joiner_stays_only_inside_non_ascii_text() {
        // A joined emoji keeps its joiner
        assert_eq!(
            plain("Vic \u{1f469}\u{200d}\u{1f4bb}", 64, "?"),
            "Vic \u{1f469}\u{200d}\u{1f4bb}"
        );
        // Next to ASCII it goes
        assert_eq!(plain("Pi\u{200d}xel", 64, "?"), "Pixel");
        // Cut just after a joiner: the joiner, now at the end, goes too
        assert_eq!(plain("\u{e9}\u{200d}\u{e9}", 2, "?"), "\u{e9}");
        // Tags and fillers the first rule missed
        assert_eq!(plain("Pixel\u{e0041}\u{3164}", 64, "?"), "Pixel");
    }
}
