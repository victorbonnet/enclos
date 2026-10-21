//! Text the sandbox wrote, made safe to show on the host.
//!
//! Which characters are shown comes from Unicode's own data (general
//! category, script, `Default_Ignorable_Code_Point`, `Ideographic`,
//! `Variation_Selector` and the emoji properties), not from a list kept by
//! hand.

use icu_properties::props::{
    BinaryProperty, DefaultIgnorableCodePoint, Emoji, EmojiModifier, EnumeratedProperty,
    ExtendedPictographic, GeneralCategory, Ideographic, Script, VariationSelector,
};

/// The most characters of the sandbox home's text shown, such as a model
/// name, counted after escaping.
const MAX_FACT_TEXT: usize = 120;

/// The most combining marks and variation selectors shown on one base
/// character: enough for Vietnamese, Arabic, pointed Hebrew and Indic text,
/// and, a judgement call, too few to stack marks over the lines around it.
const MAX_MARKS: usize = 4;

const ZERO_WIDTH_JOINER: char = '\u{200D}';

/// How the characters shown so far end, for the characters that are shown
/// only attached to the one before them.
#[derive(Clone, Copy)]
enum End {
    /// Nothing yet, or an escape: nothing to attach to.
    Nothing,
    /// A base character shown as it is, then `marks` combining marks or
    /// variation selectors on it. `emoji` when it can go on into an emoji
    /// sequence.
    Base {
        base: char,
        marks: usize,
        emoji: bool,
    },
    /// A zero width joiner between two emoji.
    Joiner,
}

/// Text the sandbox wrote, safe for a terminal: the characters below
/// escaped, then cut to at most `MAX_FACT_TEXT` characters, never inside an
/// escape and never after a joiner.
///
/// Escaped: control characters (as `\n`, `\u{1b}`), and as `\u{..}` format
/// characters (bidi controls, zero-width characters, tags), line and
/// paragraph separators, private-use and unassigned code points, and
/// default-ignorable ones such as the Hangul fillers. Characters that only
/// make sense on the one before them are shown only there, and escaped
/// anywhere else, such as at the start, where they would attach to what
/// enclos prints before the text:
/// - up to `MAX_MARKS` combining marks and variation selectors on a base
///   character shown as it is;
/// - one variation selector, right after the base and only of a kind that
///   goes on it: U+FE0E and U+FE0F after a character with Unicode's `Emoji` property
///   (which has the digits, `#` and `*`, for keycaps), the Mongolian ones
///   after a Mongolian character, and the others after an ideograph;
/// - a zero width joiner only between two `Extended_Pictographic`
///   characters both shown as they are, as in 👨‍👩‍👧.
///
/// Everything else is shown as it is, blank-looking characters such as
/// U+3000 and U+2800 too.
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
        let n = piece.chars().count();
        // A joiner is shown only with the emoji after it, one character.
        let needs = if matches!(now, End::Joiner) { n + 1 } else { n };
        if shown + needs > MAX_FACT_TEXT {
            break;
        }
        out.push_str(&piece);
        shown += n;
        end = now;
    }
    out
}

/// How the text ends once `c` is shown as it is after `end`, or `None` when
/// `c` must be escaped.
fn shows_as_itself(c: char, end: End, next: Option<char>) -> Option<End> {
    // Selectors and the joiner are default-ignorable too, so they come first.
    if VariationSelector::for_char(c) {
        return match end {
            End::Base {
                base,
                marks: 0,
                emoji,
            } if selects(c, base) => Some(End::Base {
                base,
                marks: 1,
                emoji,
            }),
            _ => None,
        };
    }
    if c == ZERO_WIDTH_JOINER {
        let between_emoji = matches!(end, End::Base { emoji: true, .. })
            && next.is_some_and(|n| {
                ExtendedPictographic::for_char(n) && shows_as_itself(n, End::Joiner, None).is_some()
            });
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

/// Whether the variation selector `selector` is of the kind that goes on
/// `base`.
fn selects(selector: char, base: char) -> bool {
    match selector {
        '\u{FE0E}' | '\u{FE0F}' => Emoji::for_char(base),
        '\u{180B}'..='\u{180F}' => Script::for_char(base) == Script::Mongolian,
        _ => Ideographic::for_char(base),
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
    fn escapes_characters_that_do_not_show_as_themselves() {
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
            ('\u{40000}', "unassigned, plane 4"),
            ('\u{2067}', "right-to-left isolate"),
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
            "\u{1820}\u{180B}",
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
        assert_eq!(printable("\u{20DD}x"), "\\u{20dd}x");
        // On an escape, they would attach to its last character.
        assert_eq!(printable("a\u{115F}\u{301}"), "a\\u{115f}\\u{301}");
        assert_eq!(printable("a\n\u{301}"), "a\\n\\u{301}");
        assert_eq!(printable("a\n\u{FE00}"), "a\\n\\u{fe00}");
        // A stack is cut at `MAX_MARKS`, and a selector counts.
        let stack = format!("a{}", "\u{301}".repeat(MAX_MARKS + 2));
        let want = format!("a{}{}", "\u{301}".repeat(MAX_MARKS), "\\u{301}".repeat(2));
        assert_eq!(printable(&stack), want);
        let stack = format!("❤\u{FE0F}{}", "\u{301}".repeat(MAX_MARKS));
        let want = format!("❤\u{FE0F}{}\\u{{301}}", "\u{301}".repeat(MAX_MARKS - 1));
        assert_eq!(printable(&stack), want);
        // A selector goes only on a character of its kind; a second one is
        // too many.
        assert_eq!(printable("a\u{FE0F}"), "a\\u{fe0f}");
        assert_eq!(printable("❤\u{FE0F}\u{FE0F}"), "❤\u{FE0F}\\u{fe0f}");
        assert_eq!(printable("a\u{FE00}b"), "a\\u{fe00}b");
        assert_eq!(printable("a\u{E0100}b"), "a\\u{e0100}b");
        assert_eq!(printable("a\u{180B}b"), "a\\u{180b}b");
        assert_eq!(printable("葛\u{180B}"), "葛\\u{180b}");
        assert_eq!(printable("\u{1820}\u{E0100}"), "\u{1820}\\u{e0100}");
    }

    #[test]
    fn a_joiner_shows_only_between_two_emoji() {
        assert_eq!(printable("a\u{200D}b"), "a\\u{200d}b");
        assert_eq!(printable("👍\u{200D}"), "👍\\u{200d}");
        assert_eq!(printable("\u{200D}👍"), "\\u{200d}👍");
        assert_eq!(printable("👍\u{200D}a"), "👍\\u{200d}a");
        // An unassigned code point can be `Extended_Pictographic`, but it
        // is escaped, so the joiner before it is too.
        assert_eq!(printable("👍\u{200D}\u{1FC00}"), "👍\\u{200d}\\u{1fc00}");
        // A skin tone after a letter does not start an emoji sequence, and
        // a mark ends one.
        assert_eq!(
            printable("a\u{1F3FD}\u{200D}\u{1F4BB}"),
            "a\u{1F3FD}\\u{200d}\u{1F4BB}"
        );
        assert_eq!(printable("👍\u{301}\u{200D}👍"), "👍\u{301}\\u{200d}👍");
        // The cut never leaves a joiner at the end.
        let family = format!("{}👨\u{200D}👩", "x".repeat(MAX_FACT_TEXT - 2));
        assert_eq!(
            printable(&family),
            format!("{}👨", "x".repeat(MAX_FACT_TEXT - 2))
        );
        let reserved = format!("{}👨\u{200D}\u{1FC00}", "x".repeat(MAX_FACT_TEXT - 3));
        assert_eq!(
            printable(&reserved),
            format!("{}👨", "x".repeat(MAX_FACT_TEXT - 3))
        );
    }
}
