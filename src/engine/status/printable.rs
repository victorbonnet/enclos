//! Text the sandbox wrote, made safe to show on the host.
//!
//! Which characters are shown comes from Unicode's own data (general
//! category, `Default_Ignorable_Code_Point`, the emoji properties), not from
//! a list kept by hand.

use icu_properties::props::{
    BinaryProperty, DefaultIgnorableCodePoint, Emoji, EmojiModifier, EnumeratedProperty,
    ExtendedPictographic, GeneralCategory, VariationSelector,
};

use super::MAX_FACT_TEXT;

/// The most combining marks shown on one base character: enough for Vietnamese, Arabic, Hebrew and Indic text, too few
/// to stack marks over the lines around it.
const MAX_MARKS: usize = 4;

const ZERO_WIDTH_JOINER: char = '\u{200D}';

/// How the characters shown so far end, for the characters that are shown
/// only attached to the one before them.
#[derive(Clone, Copy)]
enum End {
    /// Nothing yet, or an escape: nothing to attach to.
    Nothing,
    /// A base character shown as it is, then `marks` marks or a selector
    /// on it. `emoji` when it can go on into an emoji sequence.
    Base {
        base: char,
        marks: usize,
        emoji: bool,
    },
    /// A zero width joiner between two emoji.
    Joiner,
}

/// Text the sandbox wrote, safe for a terminal: every character that does
/// not show as itself escaped, then cut to at most `MAX_FACT_TEXT`
/// characters, never inside an escape and never after a joiner.
///
/// Escaped: control characters (as `\n`, `\u{1b}`), and as `\u{..}` format
/// characters (bidi controls, zero-width characters, tags), line and
/// paragraph separators, private-use and unassigned code points, and
/// default-ignorable ones such as the Hangul fillers. Characters that only
/// make sense on the one before them are shown only there, and escaped
/// anywhere else, such as at the start, where they would attach to what
/// enclos prints before the text:
/// - one variation selector right after a base character, and the emoji
///   selectors (U+FE0E, U+FE0F) only after an emoji;
/// - up to `MAX_MARKS` combining marks on a base character;
/// - a zero width joiner only between two emoji, as in 👨‍👩‍👧.
pub(super) fn printable(text: &str) -> String {
    let mut out = String::new();
    let mut shown = 0;
    let mut end = End::Nothing;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        let (piece, now) = match shows_as_itself(c, end, next) {
            Some(now) => (c.to_string(), now),
            None if c.is_control() => (c.escape_default().to_string(), End::Nothing),
            None => (c.escape_unicode().to_string(), End::Nothing),
        };
        // A joiner is shown only with the emoji after it.
        let needs = match now {
            End::Joiner => 2,
            _ => piece.chars().count(),
        };
        if shown + needs > MAX_FACT_TEXT {
            break;
        }
        out.push_str(&piece);
        shown += piece.chars().count();
        end = now;
    }
    out
}

/// How the text ends once `c` is shown as it is after `end`, or `None` when
/// `c` must be escaped.
fn shows_as_itself(c: char, end: End, next: Option<char>) -> Option<End> {
    if VariationSelector::for_char(c) {
        return match end {
            End::Base { base, marks, emoji }
                if marks == 0
                    && (!matches!(c, '\u{FE0E}' | '\u{FE0F}') || Emoji::for_char(base)) =>
            {
                Some(End::Base {
                    base,
                    marks: marks + 1,
                    emoji,
                })
            }
            _ => None,
        };
    }
    if c == ZERO_WIDTH_JOINER {
        let between_emoji = matches!(end, End::Base { emoji: true, .. })
            && next.is_some_and(ExtendedPictographic::for_char);
        return between_emoji.then_some(End::Joiner);
    }
    if DefaultIgnorableCodePoint::for_char(c) {
        return None;
    }
    match GeneralCategory::for_char(c) {
        GeneralCategory::Control
        | GeneralCategory::Format
        | GeneralCategory::LineSeparator
        | GeneralCategory::ParagraphSeparator
        | GeneralCategory::PrivateUse
        | GeneralCategory::Surrogate
        | GeneralCategory::Unassigned => None,
        GeneralCategory::NonspacingMark
        | GeneralCategory::SpacingMark
        | GeneralCategory::EnclosingMark => match end {
            End::Base { base, marks, .. } if marks < MAX_MARKS => Some(End::Base {
                base,
                marks: marks + 1,
                emoji: false,
            }),
            _ => None,
        },
        _ => {
            // A skin tone goes on into a sequence when it follows an emoji.
            let after_emoji = matches!(end, End::Base { emoji: true, .. });
            let emoji =
                ExtendedPictographic::for_char(c) || (after_emoji && EmojiModifier::for_char(c));
            Some(End::Base {
                base: c,
                marks: 0,
                emoji,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_controls_and_invisible_characters_then_cuts() {
        assert_eq!(printable("a\u{1b}[31mb\n"), "a\\u{1b}[31mb\\n");
        assert_eq!(printable("ab\u{202e}cd"), "ab\\u{202e}cd");
        assert_eq!(printable("a\u{200b}\u{feff}b"), "a\\u{200b}\\u{feff}b");
        assert_eq!(printable(&"x".repeat(500)).chars().count(), MAX_FACT_TEXT);
        // Escapes count, and an escape is never cut in half.
        let escaped = printable(&"\u{1b}".repeat(100));
        assert!(escaped.chars().count() <= MAX_FACT_TEXT);
        assert!(escaped.ends_with("\\u{1b}"), "{escaped}");
    }

    #[test]
    fn escapes_every_character_that_does_not_show_as_itself() {
        for (c, why) in [
            ('\u{115F}', "Hangul choseong filler"),
            ('\u{3164}', "Hangul filler"),
            ('\u{FFA0}', "halfwidth Hangul filler"),
            ('\u{FE0F}', "emoji selector with nothing before it"),
            ('\u{1D173}', "musical symbol begin beam, a format character"),
            ('\u{0600}', "Arabic number sign, a format character"),
            ('\u{2028}', "line separator"),
            ('\u{2029}', "paragraph separator"),
            ('\u{E000}', "private use"),
            ('\u{F0000}', "private use, plane 15"),
            ('\u{0378}', "unassigned"),
            ('\u{FFFE}', "noncharacter"),
            ('\u{034F}', "combining grapheme joiner"),
            ('\u{E0041}', "tag"),
        ] {
            let text = format!("a{c}b");
            let want = format!("a{}b", c.escape_unicode());
            assert_eq!(printable(&text), want, "{why}");
        }
    }

    #[test]
    fn keeps_text_that_shows_as_itself() {
        for text in [
            "café",
            "東京",
            "عربى",
            "👍🏽",
            "👨\u{200D}👩\u{200D}👧",
            "👩🏽\u{200D}💻",
            "❤\u{FE0F}",
            "❤\u{FE0F}\u{200D}🔥",
            "1\u{FE0F}\u{20E3}",
            "e\u{301}",
            // Vietnamese and Hindi, written with combining marks.
            "Vie\u{323}\u{302}t",
            "हिन्दी",
            "葛\u{E0100}",
            "🇫🇷",
            "gpt-6.1-sol",
        ] {
            assert_eq!(printable(text), text);
        }
    }

    #[test]
    fn marks_and_selectors_show_only_on_a_base_character() {
        // At the start they would attach to what enclos prints before.
        assert_eq!(printable("\u{301}\u{302}x"), "\\u{301}\\u{302}x");
        // On an escape, they would attach to its last character.
        assert_eq!(printable("\u{115F}\u{301}"), "\\u{115f}\\u{301}");
        assert_eq!(printable("\n\u{301}"), "\\n\\u{301}");
        // A stack is cut at `MAX_MARKS`.
        let stack = format!("a{}", "\u{301}".repeat(6));
        let want = format!("a{}{}", "\u{301}".repeat(4), "\\u{301}".repeat(2));
        assert_eq!(printable(&stack), want);
        // The emoji selectors go only on an emoji; a second one is too many.
        assert_eq!(printable("a\u{FE0F}"), "a\\u{fe0f}");
        assert_eq!(printable("❤\u{FE0F}\u{FE0F}"), "❤\u{FE0F}\\u{fe0f}");
    }

    #[test]
    fn a_joiner_shows_only_between_two_emoji() {
        assert_eq!(printable("a\u{200D}b"), "a\\u{200d}b");
        assert_eq!(printable("👍\u{200D}"), "👍\\u{200d}");
        assert_eq!(printable("\u{200D}👍"), "\\u{200d}👍");
        assert_eq!(printable("👍\u{200D}a"), "👍\\u{200d}a");
        // The cut never leaves a joiner at the end.
        let family = format!("{}👨\u{200D}👩", "x".repeat(MAX_FACT_TEXT - 2));
        assert_eq!(
            printable(&family),
            format!("{}👨", "x".repeat(MAX_FACT_TEXT - 2))
        );
    }
}
