//! Hermes's small YAML fact reader. The engine supplies bounded text; this
//! module knows Hermes's selectors and refuses values it cannot interpret.

use super::ValueAt;

pub(super) fn value(at: &ValueAt, text: &str) -> Result<Option<String>, String> {
    for key in &at.keys {
        match yaml_value(text, key) {
            Yaml::Found(value) => return Ok(Some(value)),
            Yaml::Missing => {}
            Yaml::Unsure => {
                return Err(format!("`{key}` is written in YAML enclos does not read"));
            }
        }
    }
    Ok(None)
}

/// What [`yaml_value`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Yaml {
    Found(String),
    Missing,
    /// The file uses YAML this reader does not handle, there or around the
    /// key, so any answer would be a guess.
    Unsure,
}

/// A scalar under a dotted key of a YAML mapping, such as `model.default`.
/// Enough YAML for a runtime's config: block mappings nested by spaces,
/// plain or quoted one-line scalars, and comments. Sequences and block
/// scalars are skipped whole. A tab in the indentation, a key given twice,
/// and a value that is a block scalar, an anchor, an alias, a tag, a flow
/// collection or a quoted scalar with escapes answer `Unsure`.
fn yaml_value(text: &str, key: &str) -> Yaml {
    let want: Vec<&str> = key.split('.').collect();
    let mut path: Vec<(usize, String)> = Vec::new();
    // Lines deeper than this belong to a sequence or a block scalar.
    let mut skip_deeper: Option<usize> = None;
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('\t') {
            return Yaml::Unsure;
        }
        let content = trimmed.trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if let Some(limit) = skip_deeper {
            if indent > limit {
                continue;
            }
            skip_deeper = None;
        }
        match content {
            "---" => continue,
            "..." => break,
            _ => {}
        }
        if content == "-" || content.starts_with("- ") {
            skip_deeper = Some(indent);
            continue;
        }
        let (k, rest) = match content.split_once(": ") {
            Some(pair) => pair,
            None => match content.strip_suffix(':') {
                Some(k) => (k, ""),
                // Not `key: value`: the rest of a scalar.
                None => continue,
            },
        };
        let k = k.trim().trim_matches(|c| c == '"' || c == '\'');
        while path.last().is_some_and(|(i, _)| *i >= indent) {
            path.pop();
        }
        path.push((indent, k.to_owned()));
        let rest = rest.trim();
        if rest.starts_with('|') || rest.starts_with('>') {
            skip_deeper = Some(indent);
        }
        if path
            .iter()
            .map(|(_, k)| k.as_str())
            .eq(want.iter().copied())
        {
            if found.is_some() {
                return Yaml::Unsure;
            }
            found = Some(scalar(rest));
        }
    }
    found.unwrap_or(Yaml::Missing)
}

/// The value after `key:`, on its line.
fn scalar(rest: &str) -> Yaml {
    let ends_cleanly = |after: &str| {
        let after = after.trim_start();
        after.is_empty() || after.starts_with('#')
    };
    let value = match rest.chars().next() {
        // Nothing, or a comment: the key holds a mapping, or nothing.
        None | Some('#') => return Yaml::Missing,
        Some('|' | '>' | '&' | '*' | '!' | '{' | '[' | '%' | '@' | '`') => return Yaml::Unsure,
        Some('"') => {
            let inner = &rest[1..];
            match inner.find('"') {
                Some(end) if !inner[..end].contains('\\') && ends_cleanly(&inner[end + 1..]) => {
                    &inner[..end]
                }
                _ => return Yaml::Unsure,
            }
        }
        Some('\'') => {
            let inner = &rest[1..];
            match inner.find('\'') {
                // `''` is an escaped quote.
                Some(end) if ends_cleanly(&inner[end + 1..]) => &inner[..end],
                _ => return Yaml::Unsure,
            }
        }
        Some(_) => rest.split(" #").next().unwrap_or("").trim(),
    };
    match value.is_empty() {
        true => Yaml::Missing,
        false => Yaml::Found(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_values_are_found_by_dotted_key_and_anything_unsure_says_so() {
        let found = |text: &str, key: &str| match yaml_value(text, key) {
            Yaml::Found(v) => Some(v),
            _ => None,
        };
        let text = "model:\n  default: gpt-6.1-sol # comment\n  provider: 'openai'\nother:\n  default: no\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("gpt-6.1-sol"));
        assert_eq!(found(text, "model.provider").as_deref(), Some("openai"));
        assert_eq!(yaml_value(text, "model.missing"), Yaml::Missing);
        assert_eq!(found("model: gpt\n", "model").as_deref(), Some("gpt"));
        // Siblings after a nested mapping, a value with a colon, a `#` in quotes.
        let text = "a:\n  b:\n    c: x\n  d: y\nurl: http://x:1\nq: \"a # b\"\n\"k\": v\n";
        assert_eq!(found(text, "a.d").as_deref(), Some("y"));
        assert_eq!(found(text, "a.b.d"), None);
        assert_eq!(found(text, "url").as_deref(), Some("http://x:1"));
        assert_eq!(found(text, "q").as_deref(), Some("a # b"));
        assert_eq!(found(text, "k").as_deref(), Some("v"));
        // A sequence's items do not count toward the key above them.
        let text = "model:\n  - default: listed\n    x: 1\n  default: real\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("real"));
        // A block scalar's lines are not keys.
        let text = "notes: |\n  default: inside\nmodel:\n  default: m\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("m"));
        assert_eq!(found(text, "default"), None);
        for unsure in [
            "model:\n  default: |\n    x\n",
            "model:\n  default: >\n    x\n",
            "model:\n  default: &a gpt\n",
            "model:\n  default: *a\n",
            "model:\n  default: !!str x\n",
            "model: {default: x}\n",
            "model:\n\tdefault: x\n",
            "model:\n  default: a\n  default: b\n",
            "model:\n  default: \"a\\\"b\"\n",
            "model:\n  default: 'it''s'\n",
        ] {
            assert_eq!(
                yaml_value(unsure, "model.default"),
                if unsure.starts_with("model: {") {
                    Yaml::Missing
                } else {
                    Yaml::Unsure
                },
                "{unsure:?}"
            );
        }
        assert_eq!(yaml_value("model: {default: x}\n", "model"), Yaml::Unsure);
        assert_eq!(
            yaml_value("model:\n  default: # c\n", "model.default"),
            Yaml::Missing
        );
        assert_eq!(
            yaml_value("\"model.default\": x\n", "model.default"),
            Yaml::Missing
        );
    }
}
