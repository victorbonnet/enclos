//! Hermes's small YAML fact reader, and the JSON of its install stamp and
//! of its latest release. The engine supplies bounded text; this module
//! knows Hermes's selectors and refuses values it cannot interpret.

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

/// A string of Hermes's install stamp, a JSON object. `0.0.0` is what
/// Hermes reads when it has no version, so it is none.
pub(super) fn stamp_value(at: &ValueAt, text: &str) -> Result<Option<String>, String> {
    let stamp: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "the install stamp is not JSON".to_owned())?;
    for key in &at.keys {
        match stamp.get(key) {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(s)) if s == "0.0.0" => return Ok(None),
            Some(serde_json::Value::String(s)) => return Ok(Some(s.clone())),
            Some(_) => return Err(format!("`{key}` in the install stamp is not text")),
        }
    }
    Ok(None)
}

/// The tag of the release GitHub names as Hermes's latest, when it is a
/// stable one (`vX.Y.Z`), as Hermes's installer checks it.
pub(super) fn release_tag(answer: &str) -> Result<String, String> {
    let release: serde_json::Value = serde_json::from_str(answer)
        .map_err(|_| "GitHub's answer for the latest release is not JSON".to_owned())?;
    let tag = release
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or("GitHub's answer for the latest release has no tag")?;
    let numbers: Vec<&str> = tag.strip_prefix('v').unwrap_or("").split('.').collect();
    let stable = numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit()));
    match stable {
        true => Ok(tag.to_owned()),
        false => Err("the latest release's tag is not a stable release's".to_owned()),
    }
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

/// `text` without its top-level `key` and what it holds, such as the
/// `model` block Hermes writes for `/model --global`; `None` when the file
/// uses YAML this reader does not follow, which the caller compares whole:
/// a tab in the indentation, a document marker or directive, a flow
/// collection at the left margin, an anchor, alias or merge key anywhere
/// (an anchor on `key` reused elsewhere would carry its change there), a
/// sequence at the left margin under `key`, or `key` given twice. The text
/// of a block scalar (`|`, `>`), such as a prompt, is not YAML and is never
/// read for these. The channel's `model.py` follows the same rules.
pub(super) fn without_top_level(text: &str, key: &str) -> Option<String> {
    fn indent(line: &str) -> usize {
        line.len() - line.trim_start_matches(' ').len()
    }
    // `&name` or `*name` where a YAML token starts.
    fn anchor_or_alias(line: &str) -> bool {
        let chars: Vec<char> = line.chars().collect();
        chars.iter().enumerate().any(|(i, &c)| {
            (c == '&' || c == '*')
                && (i == 0 || matches!(chars[i - 1], ' ' | '[' | '{' | ','))
                && chars
                    .get(i + 1)
                    .is_some_and(|n| n.is_alphanumeric() || *n == '_' || *n == '-')
        })
    }
    fn unsure(line: &str) -> bool {
        let leading = &line[..line.len() - line.trim_start().len()];
        let trimmed = line.trim_start();
        leading.contains('\t')
            || line.starts_with("---")
            || line.starts_with("...")
            || line.starts_with('%')
            || line.starts_with('{')
            || line.starts_with('[')
            || trimmed.starts_with("<<")
            || anchor_or_alias(line)
    }
    // `key: |`, `- >-`: the lines below, deeper, are the scalar's text.
    fn opens_block_scalar(line: &str) -> bool {
        let content = line.split(" #").next().unwrap_or(line).trim_end();
        let Some(last) = content.split(' ').next_back() else {
            return false;
        };
        let before = content[..content.len() - last.len()].trim_end();
        let mut marks = last.chars();
        matches!(marks.next(), Some('|' | '>'))
            && marks.all(|c| c == '+' || c == '-' || c.is_ascii_digit())
            && (before.ends_with(':') || before.ends_with('-'))
    }
    fn top_key(line: &str) -> Option<&str> {
        let starts = line.chars().next();
        (starts.is_some_and(|c| !c.is_whitespace() && c != '#' && c != '-'))
            .then(|| line.split(':').next().unwrap_or("").trim())
    }
    let mut kept = Vec::new();
    let mut inside = false;
    let mut seen = false;
    // The indentation of the line that opened a block scalar.
    let mut scalar: Option<usize> = None;
    for line in text.lines() {
        if let Some(at) = scalar {
            if line.trim().is_empty() || indent(line) > at {
                if !inside {
                    kept.push(line);
                }
                continue;
            }
            scalar = None;
        }
        if unsure(line) {
            return None;
        }
        match top_key(line) {
            Some(name)
                if name == key || name == format!("\"{key}\"") || name == format!("'{key}'") =>
            {
                if seen {
                    return None;
                }
                seen = true;
                inside = true;
            }
            Some(_) => {
                inside = false;
                kept.push(line);
            }
            // A sequence item at the left margin is the block's own value.
            None if inside && line.starts_with('-') => return None,
            None if inside => {}
            None => kept.push(line),
        }
        if opens_block_scalar(line) {
            scalar = Some(indent(line));
        }
    }
    Some(kept.join("\n"))
}

/// `text` without the `keys` of its top-level `parent` mapping, each with a
/// value on its own line, such as the `approvals` switches Hermes reads from
/// disk for each command; the `parent` line goes too when no other setting
/// is left under it, so a block Hermes adds for them alone changes nothing.
/// Trailing blank lines are dropped. `None` when [`without_top_level`]
/// cannot read the file, `parent` has a value on its own line (a flow
/// mapping, say), or one of `keys` holds anything but a one-line scalar:
/// the caller then compares the file as it did before.
pub(super) fn without_nested(text: &str, parent: &str, keys: &[&str]) -> Option<String> {
    // The reader's own checks: YAML it does not follow, `parent` twice or as
    // a sequence.
    without_top_level(text, parent)?;
    fn indent(line: &str) -> usize {
        line.len() - line.trim_start_matches(' ').len()
    }
    fn named(line: &str, name: &str) -> bool {
        let key = line.split(':').next().unwrap_or("").trim();
        key == name || key == format!("\"{name}\"") || key == format!("'{name}'")
    }
    // What follows a key's colon, without a comment.
    fn value(line: &str) -> &str {
        line.split_once(':')
            .map_or("", |(_, rest)| rest.split(" #").next().unwrap_or("").trim())
    }
    fn setting(line: &str) -> bool {
        !line.trim().is_empty() && !line.trim_start().starts_with('#')
    }
    let lines: Vec<&str> = text.lines().collect();
    let header = lines.iter().position(|line| {
        !line.starts_with(|c: char| c.is_whitespace() || c == '#' || c == '-')
            && named(line, parent)
    });
    let mut out: Vec<&str> = Vec::new();
    match header {
        None => out.extend(&lines),
        Some(header) => {
            if !value(lines[header]).is_empty() {
                return None;
            }
            let end = lines[header + 1..]
                .iter()
                .position(|line| setting(line) && indent(line) == 0)
                .map_or(lines.len(), |at| header + 1 + at);
            let block = &lines[header + 1..end];
            let child = block
                .iter()
                .find(|line| setting(line))
                .map(|line| indent(line));
            let mut kept: Vec<&str> = Vec::new();
            let mut after_dropped = false;
            for line in block {
                if setting(line) && Some(indent(line)) == child {
                    if keys.iter().any(|key| named(line, key)) {
                        let one_line = value(line);
                        if one_line.is_empty()
                            || one_line.starts_with(|c: char| "|>{[&*!".contains(c))
                        {
                            return None;
                        }
                        after_dropped = true;
                        continue;
                    }
                    after_dropped = false;
                } else if after_dropped && setting(line) {
                    // A dropped value that goes on below its key.
                    return None;
                }
                kept.push(*line);
            }
            out.extend(&lines[..header]);
            if kept.iter().any(|line| setting(line)) {
                out.push(lines[header]);
                out.extend(kept);
            }
            out.extend(&lines[end..]);
        }
    }
    while out.last().is_some_and(|line| line.trim().is_empty()) {
        out.pop();
    }
    Some(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_stamp_gives_the_base_version_and_its_placeholder_is_none() {
        let at = ValueAt {
            file: crate::runtime::HomePath::new(".hermes/hermes-agent/install-stamp.json").unwrap(),
            keys: vec!["baseVersion".into()],
        };
        // As Hermes's installer wrote it on a Mac, 2026-11-13.
        let stamp = r#"{"schemaVersion": 2, "commit": "3b42157", "source": "git",
            "baseVersion": "0.23.1", "displayVersion": "0.23.1", "distance": 0}"#;
        assert_eq!(stamp_value(&at, stamp), Ok(Some("0.23.1".into())));
        assert_eq!(stamp_value(&at, r#"{"baseVersion": "0.0.0"}"#), Ok(None));
        assert_eq!(stamp_value(&at, r#"{"source": "git"}"#), Ok(None));
        assert!(stamp_value(&at, r#"{"baseVersion": 23}"#).is_err());
        assert!(stamp_value(&at, "baseVersion: 0.23.1").is_err());
    }

    #[test]
    fn only_a_stable_release_tag_is_the_latest_release() {
        let answer = |tag: &str| format!(r#"{{"tag_name": "{tag}", "name": "Hermes"}}"#);
        assert_eq!(release_tag(&answer("v0.23.2")), Ok("v0.23.2".into()));
        for tag in ["v0.24.0-rc.1", "0.23.2", "v0.23", "canary", "v1.2.3.4"] {
            assert!(release_tag(&answer(tag)).is_err(), "{tag}");
        }
        assert!(release_tag(r#"{"message": "API rate limit exceeded"}"#).is_err());
        assert!(release_tag("<html>").is_err());
    }

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

    #[test]
    fn a_change_of_the_model_block_alone_leaves_the_rest_the_same() {
        let before = "# Hermes\nmodel:\n  default: model-1\n  provider: provider-a\n\n  base_url: ''\nterminal:\n  backend: local\nplatforms:\n  - x\n";
        let after = "# Hermes\nmodel:\n  default: model-2\n  provider: provider-b\nterminal:\n  backend: local\nplatforms:\n  - x\n";
        let one_line = "# Hermes\nmodel: model-3\nterminal:\n  backend: local\nplatforms:\n  - x\n";
        let rest = without_top_level(before, "model").unwrap();
        assert_eq!(
            rest,
            "# Hermes\nterminal:\n  backend: local\nplatforms:\n  - x"
        );
        assert_eq!(without_top_level(after, "model").unwrap(), rest);
        assert_eq!(without_top_level(one_line, "model").unwrap(), rest);
        let other = after.replace("backend: local", "backend: docker");
        assert_ne!(without_top_level(&other, "model").unwrap(), rest);
        // Another key whose name starts the same is kept.
        assert_eq!(
            without_top_level("model_catalog:\n  x: 1\n", "model").unwrap(),
            "model_catalog:\n  x: 1"
        );
    }

    #[test]
    fn yaml_this_reader_does_not_follow_is_compared_whole() {
        for unsure in [
            "model:\n\tdefault: x\n",
            "---\nmodel:\n  default: x\n",
            "model:\n  default: x\nmodel:\n  default: y\n",
            "{model: x}\n",
            "base: &b\n  x: 1\nmodel:\n  <<: *b\n",
            "model:\n- x\n",
            "model:  &route\n  default: x\nvision: *route\n",
            "model: !!map &route\n  default: x\n",
            "model:\n  default: x\nfallbacks: [*route]\n",
            "[model, x]\n",
            "model:\n \tdefault: x\n",
        ] {
            assert_eq!(without_top_level(unsure, "model"), None, "{unsure:?}");
        }
    }

    #[test]
    fn the_text_of_a_block_scalar_is_not_read_as_yaml() {
        // A prompt in markdown: bullets and emphasis that, read as YAML,
        // would look like aliases.
        let before = "model:\n  default: model-1\nagent:\n  system_prompt: |\n    - **Be brief**\n    Note: *always* cite.\n\n    ---\n  max_turns: 9\n";
        let after = before.replace("model-1", "model-2");
        let rest = without_top_level(before, "model").expect("read");
        assert_eq!(rest, without_top_level(&after, "model").unwrap());
        assert!(
            rest.contains("    - **Be brief**"),
            "the prompt is kept: {rest}"
        );
        let other = after.replace("max_turns: 9", "max_turns: 10");
        assert_ne!(rest, without_top_level(&other, "model").unwrap());
        // The same text outside a block scalar is not followed.
        assert_eq!(
            without_top_level("model: x\nnote: *always*\n", "model"),
            None
        );
    }

    #[test]
    fn nested_keys_with_one_line_values_are_left_out_and_nothing_else() {
        let keys = &["destructive_slash_confirm", "mcp_reload_confirm"];
        let before =
            "# Hermes\napprovals:\n  timeout: 60\n  # a note\nterminal:\n  backend: local\n";
        let rest = without_nested(before, "approvals", keys).unwrap();
        assert_eq!(rest, before.trim_end());
        let after = before.replace(
            "  # a note\n",
            "  # a note\n  destructive_slash_confirm: false # off\n",
        );
        assert_eq!(without_nested(&after, "approvals", keys).unwrap(), rest);
        let quoted = before.replace(
            "  timeout: 60\n",
            "  timeout: 60\n  'mcp_reload_confirm': \"false\"\n",
        );
        assert_eq!(without_nested(&quoted, "approvals", keys).unwrap(), rest);
        // A block left with these keys alone goes, its header too.
        let alone =
            "terminal:\n  backend: local\napprovals:\n  destructive_slash_confirm: false\n\n";
        assert_eq!(
            without_nested(alone, "approvals", keys).unwrap(),
            "terminal:\n  backend: local"
        );
        // The same key elsewhere, deeper or under another block, is kept.
        let deeper = "approvals:\n  timeout: 60\n  extra:\n    destructive_slash_confirm: false\n";
        assert_eq!(
            without_nested(deeper, "approvals", keys).unwrap(),
            deeper.trim_end()
        );
        let other = "display:\n  destructive_slash_confirm: false\n";
        assert_eq!(
            without_nested(other, "approvals", keys).unwrap(),
            other.trim_end()
        );
        // A value this reader cannot tell from a one-line scalar: compared whole.
        for unsure in [
            "approvals: {destructive_slash_confirm: false}\n",
            "approvals:\n  destructive_slash_confirm:\n    x: 1\n",
            "approvals:\n  destructive_slash_confirm: |\n    false\n",
            "approvals:\n  destructive_slash_confirm: false\n    true\n",
            "approvals:\n\tdestructive_slash_confirm: false\n",
        ] {
            assert_eq!(
                without_nested(unsure, "approvals", keys),
                None,
                "{unsure:?}"
            );
        }
    }

    #[test]
    fn a_model_key_deeper_in_another_block_still_counts() {
        let before = "model:\n  default: m\nauxiliary:\n  vision:\n    model: small-1\n";
        let after = before.replace("small-1", "small-2");
        assert_ne!(
            without_top_level(before, "model").unwrap(),
            without_top_level(&after, "model").unwrap()
        );
    }
}
