//! The price list (issue #343, design §11, Usage): what a model's tokens
//! cost, in US dollars per million tokens, from which enclos estimates the
//! cost of an agent's usage.
//!
//! The list ships inside enclos (`src/prices.toml`): a part kept by hand,
//! which wins, and a part `scripts/update_prices.py` generates from a
//! pinned LiteLLM commit, through a reviewed pull request. enclos fetches
//! no price when it runs. `prices.toml` in enclos's config folder, in the
//! same format, overrides it, per provider and model.
//!
//! The estimate is worked out when usage is read, from the list as it is
//! then, so a corrected price applies to past usage too. A model the list
//! does not have has an unknown cost, never $0; a provider the list marks
//! `included` is a subscription, whose tokens cost nothing in dollars but
//! count against its limits. Rates are base rates: a provider's higher
//! rate for a long prompt, a batch discount, and a 1-hour cache write's
//! dearer rate are not applied, since a runtime's records sum many calls.

use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use enclos_protocol::usage::UsageCost;

/// The list enclos ships.
const BUNDLED: &str = include_str!("prices.toml");
/// The most bytes of an override file enclos reads.
const MAX_OVERRIDE_BYTES: u64 = 1 << 20;
/// The most a rate may be, in dollars per million tokens: far above any
/// model's, low enough that no estimate overflows before it saturates.
const MAX_RATE: f64 = 1_000_000.0;
/// The most characters of a provider's or a model's name.
const MAX_NAME_CHARS: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    providers: BTreeMap<String, ProviderEntry>,
    #[serde(default)]
    models: Vec<ModelEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderEntry {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    included: bool,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelEntry {
    provider: String,
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    input: f64,
    output: f64,
    #[serde(default)]
    cache_read: Option<f64>,
    #[serde(default)]
    cache_write: Option<f64>,
    #[serde(default)]
    source: Option<String>,
}

/// Where a price came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The list enclos ships.
    Bundled,
    /// The override file in enclos's config folder.
    Override,
}

/// A model's rates, in US dollars per million tokens. A cache rate the
/// provider does not set apart is priced as input.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Rates {
    pub input: f64,
    pub output: f64,
    pub cache_read: Option<f64>,
    pub cache_write: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelPrice {
    pub provider: String,
    pub id: String,
    pub aliases: Vec<String>,
    pub rates: Rates,
    /// Where its rates were taken from: a pricing page, or
    /// `litellm@<commit>` for a generated entry.
    pub source: Option<String>,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub aliases: Vec<String>,
    /// A subscription: its tokens' cost is included.
    pub included: bool,
    pub source: Option<String>,
    pub origin: Origin,
}

/// What the list says of a model.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Price<'a> {
    Rates(&'a ModelPrice),
    /// On a subscription, the provider named.
    Included(&'a ProviderInfo),
    /// No price: the cost is unknown.
    Unknown,
}

/// Token counts to price, each `None` when the runtime does not count it.
/// `input` excludes cache reads and writes; reasoning is part of output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cache_read: Option<u64>,
    pub cache_write: Option<u64>,
}

impl Counts {
    pub fn total(&self) -> u64 {
        [self.input, self.output, self.cache_read, self.cache_write]
            .into_iter()
            .flatten()
            .fold(0, u64::saturating_add)
    }
}

impl From<enclos_protocol::usage::UsageTokens> for Counts {
    fn from(t: enclos_protocol::usage::UsageTokens) -> Counts {
        Counts {
            input: t.input,
            output: t.output,
            cache_read: t.cache_read,
            cache_write: t.cache_write,
        }
    }
}

/// The price list: the bundled one, with the override file's entries in
/// place of or beside its own.
#[derive(Debug, Clone)]
pub struct PriceList {
    providers: BTreeMap<String, ProviderInfo>,
    /// Each provider's name and alias, lowercase, to its name.
    names: HashMap<String, String>,
    models: Vec<ModelPrice>,
    /// `(provider, id or alias)`, lowercase, to its place in `models`.
    index: HashMap<(String, String), usize>,
}

/// The list as it was read: the override file named, and what kept it
/// from being read, when something did.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub list: PriceList,
    pub override_file: PathBuf,
    pub override_read: OverrideRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideRead {
    /// There is none.
    Absent,
    /// Read: this many models and providers.
    Read { models: usize, providers: usize },
    /// Not read, and why: the bundled list is used alone.
    Refused(String),
}

impl PriceList {
    /// The list enclos ships. It is read at build time and checked by a
    /// test, so it always reads.
    pub fn bundled() -> PriceList {
        static BUNDLED_LIST: std::sync::OnceLock<PriceList> = std::sync::OnceLock::new();
        BUNDLED_LIST
            .get_or_init(|| {
                let mut list = PriceList::empty();
                if let Err(why) = list.add(BUNDLED, Origin::Bundled) {
                    // Checked by a test (`the_bundled_list_reads_and_prices_a_known_model`).
                    unreachable!("the bundled price list does not read: {why}")
                }
                list
            })
            .clone()
    }

    fn empty() -> PriceList {
        PriceList {
            providers: BTreeMap::new(),
            names: HashMap::new(),
            models: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// The bundled list, with the override file at `path` when there is
    /// one. An override that cannot be read leaves the bundled list alone,
    /// and says why.
    pub fn load(path: &Path) -> Loaded {
        let bundled = PriceList::bundled();
        let override_read = match read_override(path) {
            Ok(None) => OverrideRead::Absent,
            Ok(Some(text)) => {
                let mut list = bundled.clone();
                match list.add(&text, Origin::Override) {
                    Ok((models, providers)) => {
                        return Loaded {
                            list,
                            override_file: path.to_owned(),
                            override_read: OverrideRead::Read { models, providers },
                        };
                    }
                    Err(why) => OverrideRead::Refused(why),
                }
            }
            Err(why) => OverrideRead::Refused(why),
        };
        Loaded {
            list: bundled,
            override_file: path.to_owned(),
            override_read,
        }
    }

    /// Adds a file's providers and models, in place of those of the same
    /// name: all or nothing. Returns how many models and providers it had.
    fn add(&mut self, text: &str, origin: Origin) -> Result<(usize, usize), String> {
        let file: File = toml::from_str(text).map_err(|e| format!("is not a price list: {e}"))?;
        let mut next = self.clone();
        for (name, p) in &file.providers {
            let key = checked_name(name, "a provider")?;
            let mut aliases = Vec::new();
            for alias in &p.aliases {
                aliases.push(checked_name(alias, "a provider's alias")?);
            }
            // A provider named again replaces the earlier one, aliases too.
            if let Some(old) = next.providers.remove(&key) {
                for alias in old.aliases {
                    next.names.remove(&alias.to_lowercase());
                }
            }
            for n in std::iter::once(&key).chain(&aliases) {
                let lower = n.to_lowercase();
                if let Some(other) = next.names.get(&lower).filter(|o| **o != key) {
                    return Err(format!("names {n} for both {other} and {key}"));
                }
                next.names.insert(lower, key.clone());
            }
            next.providers.insert(
                key.clone(),
                ProviderInfo {
                    name: key,
                    aliases,
                    included: p.included,
                    source: p.source.clone(),
                    origin,
                },
            );
        }
        let mut seen = Vec::new();
        for m in &file.models {
            let id = checked_name(&m.id, "a model")?;
            let Some(provider) = next.names.get(&m.provider.to_lowercase()).cloned() else {
                return Err(format!(
                    "prices {id} under provider {}, which it does not name under [providers]",
                    m.provider
                ));
            };
            if next.providers[&provider].included {
                return Err(format!(
                    "prices {id} under {provider}, a subscription whose cost is included"
                ));
            }
            let mut aliases = Vec::new();
            for alias in &m.aliases {
                aliases.push(checked_name(alias, "a model's alias")?);
            }
            let rates = Rates {
                input: checked_rate(m.input, &id)?,
                output: checked_rate(m.output, &id)?,
                cache_read: m.cache_read.map(|r| checked_rate(r, &id)).transpose()?,
                cache_write: m.cache_write.map(|r| checked_rate(r, &id)).transpose()?,
            };
            let key = (provider.clone(), id.to_lowercase());
            if seen.contains(&key) {
                return Err(format!("prices {id} of {provider} twice"));
            }
            seen.push(key);
            next.put(ModelPrice {
                provider,
                id,
                aliases,
                rates,
                source: m.source.clone(),
                origin,
            });
        }
        *self = next;
        Ok((file.models.len(), file.providers.len()))
    }

    /// Puts a model in, in place of the one of the same provider and id,
    /// and of any whose alias it now takes.
    fn put(&mut self, price: ModelPrice) {
        let names: Vec<String> = std::iter::once(&price.id)
            .chain(&price.aliases)
            .map(|n| n.to_lowercase())
            .collect();
        // The entry of this id, not one this id is an alias of.
        let same = self
            .index
            .get(&(price.provider.clone(), price.id.to_lowercase()))
            .copied()
            .filter(|&at| self.models[at].id.eq_ignore_ascii_case(&price.id));
        let at = match same {
            Some(at) => {
                // Its earlier names go: the new entry says its own.
                let old = &self.models[at];
                for n in std::iter::once(&old.id).chain(&old.aliases) {
                    self.index.remove(&(old.provider.clone(), n.to_lowercase()));
                }
                self.models[at] = price.clone();
                at
            }
            None => {
                self.models.push(price.clone());
                self.models.len() - 1
            }
        };
        for n in names {
            self.index.insert((price.provider.clone(), n), at);
        }
    }

    pub fn providers(&self) -> impl Iterator<Item = &ProviderInfo> {
        self.providers.values()
    }

    pub fn models(&self) -> &[ModelPrice] {
        &self.models
    }

    /// The provider a runtime's name for it stands for.
    pub fn provider(&self, name: &str) -> Option<&ProviderInfo> {
        self.names
            .get(&name.trim().to_lowercase())
            .and_then(|n| self.providers.get(n))
    }

    /// What the list says of `model` as `provider` serves it, each as the
    /// runtime names it.
    ///
    /// A provider the list marks `included` is a subscription, whatever
    /// the model. Otherwise the model is looked for under the provider: as
    /// named, without a date suffix (`-20260101`), and with dashes for
    /// dots (`claude-opus-4.6`). A model named with its maker
    /// (`anthropic/claude-opus-4-6`, as OpenRouter and Nous name them) is
    /// looked for under its maker when the provider is not in the list.
    /// Without a provider, it is looked for under each, in name order. A
    /// provider not in the list, serving a model not named with its
    /// maker, has no price: a model of the same name elsewhere may cost
    /// something else there.
    pub fn find(&self, provider: Option<&str>, model: Option<&str>) -> Price<'_> {
        let provider = provider
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty() && p != "auto" && p != "unknown");
        let known = provider.as_deref().and_then(|p| self.names.get(p));
        if let Some(name) = known
            && self.providers[name].included
        {
            return Price::Included(&self.providers[name]);
        }
        let Some(model) = model
            .map(|m| m.trim().to_lowercase())
            .filter(|m| !m.is_empty())
        else {
            return Price::Unknown;
        };
        let (maker, bare) = match model.split_once('/') {
            Some((maker, bare)) => match self.names.get(maker) {
                Some(maker) => (Some(maker), bare.to_owned()),
                None => (None, model.clone()),
            },
            None => (None, model.clone()),
        };
        let under: Vec<&String> = match (known, maker, &provider) {
            (Some(p), _, _) => vec![p],
            (None, Some(m), _) => vec![m],
            (None, None, Some(_)) => return Price::Unknown,
            (None, None, None) => self.providers.keys().collect(),
        };
        for p in under {
            if self.providers[p].included {
                continue;
            }
            for name in candidates(&bare) {
                if let Some(&at) = self.index.get(&(p.clone(), name)) {
                    return Price::Rates(&self.models[at]);
                }
            }
        }
        Price::Unknown
    }

    /// What `counts` of `model`, as `provider` serves it, cost.
    pub fn cost(&self, provider: Option<&str>, model: Option<&str>, counts: Counts) -> UsageCost {
        let total = counts.total();
        match self.find(provider, model) {
            Price::Included(_) => UsageCost {
                included: total,
                ..UsageCost::default()
            },
            Price::Unknown => UsageCost {
                unpriced: total,
                ..UsageCost::default()
            },
            Price::Rates(price) => UsageCost {
                usd_micros: price.rates.micros(counts),
                ..UsageCost::default()
            },
        }
    }
}

impl Rates {
    /// Millionths of a dollar for `counts`: a rate per million tokens
    /// times a count of tokens. Rounded, and at most `u64::MAX`.
    pub fn micros(&self, counts: Counts) -> u64 {
        let part = |n: Option<u64>, rate: f64| n.unwrap_or(0) as f64 * rate;
        let sum = part(counts.input, self.input)
            + part(counts.output, self.output)
            + part(counts.cache_read, self.cache_read.unwrap_or(self.input))
            + part(counts.cache_write, self.cache_write.unwrap_or(self.input));
        let sum = sum.round();
        if !sum.is_finite() || sum <= 0.0 {
            0
        } else if sum >= u64::MAX as f64 {
            u64::MAX
        } else {
            sum as u64
        }
    }
}

/// The names a model may be listed under: as given, without a date
/// suffix, and with dashes for dots, each once.
fn candidates(model: &str) -> Vec<String> {
    let mut out = vec![model.to_owned()];
    let undated = without_date(model);
    for name in [undated.to_owned(), model.replace('.', "-")] {
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// `model` without a trailing `-YYYYMMDD` or `-YYYY-MM-DD`.
fn without_date(model: &str) -> &str {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if let Some((head, tail)) = model.rsplit_once('-')
        && tail.len() == 8
        && digits(tail)
    {
        return head;
    }
    let parts: Vec<&str> = model.rsplitn(4, '-').collect();
    if let [day, month, year, head] = parts[..]
        && year.len() == 4
        && month.len() == 2
        && day.len() == 2
        && digits(year)
        && digits(month)
        && digits(day)
    {
        return head;
    }
    model
}

fn checked_name(name: &str, what: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || is_invisible(c))
    {
        return Err(format!(
            "has {what} name that is empty, longer than {MAX_NAME_CHARS} characters, or holds a space or a hidden character"
        ));
    }
    Ok(name.to_owned())
}

/// Characters a terminal draws as nothing, or that reorder the text around
/// them.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
}

fn checked_rate(rate: f64, model: &str) -> Result<f64, String> {
    if !rate.is_finite() || !(0.0..=MAX_RATE).contains(&rate) {
        return Err(format!(
            "prices {model} at a rate that is not between 0 and {MAX_RATE} dollars per million tokens"
        ));
    }
    Ok(rate)
}

/// The override file's text, or none when there is no file: a plain file,
/// not a link, of at most [`MAX_OVERRIDE_BYTES`].
fn read_override(path: &Path) -> Result<Option<String>, String> {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits();
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(flags as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot be opened: {e}")),
    };
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("is not a plain file".into());
    }
    let mut text = String::new();
    file.take(MAX_OVERRIDE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot be read: {e}"))?;
    if text.len() as u64 > MAX_OVERRIDE_BYTES {
        return Err(format!("is larger than {MAX_OVERRIDE_BYTES} bytes"));
    }
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"
[providers.anthropic]
[providers.openai]
aliases = ["openai-api"]
[providers.openai-codex]
included = true

[[models]]
provider = "anthropic"
id = "claude-opus-5-5"
aliases = ["claude-opus-latest"]
input = 4.0
output = 20.0
cache_read = 0.2
cache_write = 5.0

[[models]]
provider = "openai"
id = "gpt-5.5"
input = 5.0
output = 30.0
"#;

    fn list(text: &str) -> PriceList {
        let mut list = PriceList::empty();
        list.add(text, Origin::Bundled).unwrap();
        list
    }

    fn refused(text: &str) -> String {
        PriceList::empty()
            .add(text, Origin::Bundled)
            .err()
            .unwrap_or_else(|| panic!("taken: {text}"))
    }

    fn id(price: Price<'_>) -> Option<String> {
        match price {
            Price::Rates(p) => Some(format!("{}/{}", p.provider, p.id)),
            Price::Included(p) => Some(format!("{} included", p.name)),
            Price::Unknown => None,
        }
    }

    #[test]
    fn the_bundled_list_reads_and_prices_a_known_model() {
        let list = PriceList::bundled();
        assert!(list.models().len() > 100, "{}", list.models().len());
        assert!(list.provider("openai-codex").unwrap().included);
        assert!(list.provider("GitHub-Copilot").unwrap().included);
        // Every entry names where its rates came from.
        assert!(list.models().iter().all(|m| m.source.is_some()));
        let Price::Rates(opus) = list.find(Some("anthropic"), Some("claude-opus-5-5")) else {
            panic!("no price for claude-opus-5-5")
        };
        assert!(opus.rates.input > 0.0 && opus.rates.output > opus.rates.input);
    }

    #[test]
    fn an_override_named_as_another_models_alias_is_a_model_of_its_own() {
        let mut list = list(LIST);
        list.add(
            "[[models]]\nprovider = \"anthropic\"\nid = \"claude-opus-latest\"\ninput = 1.0\noutput = 1.0\n",
            Origin::Override,
        )
        .unwrap();
        let rate = |m: &str| match list.find(Some("anthropic"), Some(m)) {
            Price::Rates(p) => p.rates.input,
            _ => panic!("no price for {m}"),
        };
        assert_eq!(
            (rate("claude-opus-5-5"), rate("claude-opus-latest")),
            (4.0, 1.0)
        );
    }

    #[test]
    fn a_model_is_found_as_named_by_alias_without_its_date_and_with_dashes_for_dots() {
        let list = list(LIST);
        let found = |p: Option<&str>, m: &str| id(list.find(p, Some(m)));
        let opus = Some("anthropic/claude-opus-5-5".to_owned());
        assert_eq!(found(Some("anthropic"), "claude-opus-5-5"), opus);
        assert_eq!(found(Some("Anthropic"), " Claude-Opus-5-5 "), opus);
        assert_eq!(found(Some("anthropic"), "claude-opus-latest"), opus);
        assert_eq!(found(Some("anthropic"), "claude-opus-5-5-20261101"), opus);
        assert_eq!(found(Some("anthropic"), "claude-opus-5-5-2026-11-01"), opus);
        assert_eq!(found(Some("anthropic"), "claude-opus-5.5"), opus);
        // A provider's alias.
        assert_eq!(
            found(Some("openai-api"), "gpt-5.5"),
            Some("openai/gpt-5.5".into())
        );
        // A model of another provider is not found under this one.
        assert_eq!(found(Some("openai"), "claude-opus-5-5"), None);
    }

    #[test]
    fn a_subscription_is_included_whatever_the_model() {
        let list = list(LIST);
        assert_eq!(
            id(list.find(Some("openai-codex"), Some("gpt-5.5"))),
            Some("openai-codex included".into())
        );
        assert_eq!(
            id(list.find(Some("openai-codex"), None)),
            Some("openai-codex included".into())
        );
        let cost = list.cost(
            Some("openai-codex"),
            Some("gpt-5.5"),
            Counts {
                input: Some(10),
                output: Some(5),
                ..Counts::default()
            },
        );
        assert_eq!((cost.usd_micros, cost.included, cost.unpriced), (0, 15, 0));
    }

    #[test]
    fn a_model_named_with_its_maker_is_priced_at_the_makers_rates_through_a_provider_not_listed() {
        let list = list(LIST);
        assert_eq!(
            id(list.find(Some("openrouter"), Some("anthropic/claude-opus-5-5"))),
            Some("anthropic/claude-opus-5-5".into())
        );
        assert_eq!(
            id(list.find(None, Some("openai/gpt-5.5"))),
            Some("openai/gpt-5.5".into())
        );
        // A provider not listed, serving a model without its maker: unknown,
        // whatever another provider charges for a model of that name.
        assert_eq!(id(list.find(Some("ollama"), Some("gpt-5.5"))), None);
        // No provider: each is looked in.
        assert_eq!(
            id(list.find(None, Some("gpt-5.5"))),
            Some("openai/gpt-5.5".into())
        );
        assert_eq!(
            id(list.find(Some("auto"), Some("gpt-5.5"))),
            Some("openai/gpt-5.5".into())
        );
        assert_eq!(id(list.find(None, Some("llama-3"))), None);
        assert_eq!(id(list.find(Some("anthropic"), None)), None);
    }

    #[test]
    fn a_cost_is_millionths_of_a_dollar_with_cache_rates_falling_back_to_input() {
        let list = list(LIST);
        let counts = Counts {
            input: Some(1_000_000),
            output: Some(100_000),
            cache_read: Some(2_000_000),
            cache_write: Some(10_000),
        };
        // 1M × $4 + 0.1M × $20 + 2M × $0.20 + 0.01M × $5 = $6.45.
        let opus = list.cost(Some("anthropic"), Some("claude-opus-5-5"), counts);
        assert_eq!(opus.usd_micros, 6_450_000);
        assert_eq!((opus.included, opus.unpriced), (0, 0));
        // No cache rates: cache tokens at the input rate, $5 a million.
        // 1M × $5 + 0.1M × $30 + 2.01M × $5 = $18.05.
        let gpt = list.cost(Some("openai"), Some("gpt-5.5"), counts);
        assert_eq!(gpt.usd_micros, 18_050_000);
        // Unknown: every token unpriced, no dollars.
        let unknown = list.cost(Some("nous"), Some("hermes-5"), counts);
        assert_eq!((unknown.usd_micros, unknown.unpriced), (0, 3_110_000));
        // A count not kept prices as none.
        let some = Counts {
            input: Some(1),
            ..Counts::default()
        };
        assert_eq!(
            list.cost(Some("anthropic"), Some("claude-opus-5-5"), some)
                .usd_micros,
            4
        );
        // A huge count stops at the most a cost holds.
        let all = Counts {
            output: Some(u64::MAX),
            ..Counts::default()
        };
        let rates = Rates {
            input: MAX_RATE,
            output: MAX_RATE,
            cache_read: None,
            cache_write: None,
        };
        assert_eq!(rates.micros(all), u64::MAX);
    }

    #[test]
    fn an_override_replaces_a_price_adds_a_model_and_a_provider_and_says_what_it_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.toml");
        let absent = PriceList::load(&path);
        assert_eq!(absent.override_read, OverrideRead::Absent);
        std::fs::write(
            &path,
            r#"
[providers.nous]
[[models]]
provider = "nous"
id = "hermes-5"
input = 1.0
output = 2.0
source = "my invoice"

[[models]]
provider = "anthropic"
id = "claude-opus-5-5"
input = 3.0
output = 15.0
"#,
        )
        .unwrap();
        let loaded = PriceList::load(&path);
        assert_eq!(
            loaded.override_read,
            OverrideRead::Read {
                models: 2,
                providers: 1
            }
        );
        let Price::Rates(opus) = loaded.list.find(Some("anthropic"), Some("claude-opus-5-5"))
        else {
            panic!("no price")
        };
        assert_eq!((opus.rates.input, opus.origin), (3.0, Origin::Override));
        // Its cache rates are its own: none, so input's.
        assert_eq!(opus.rates.cache_read, None);
        let Price::Rates(hermes) = loaded.list.find(Some("nous"), Some("hermes-5")) else {
            panic!("no price")
        };
        assert_eq!(hermes.source.as_deref(), Some("my invoice"));
    }

    #[test]
    fn an_override_that_does_not_read_leaves_the_bundled_list_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prices.toml");
        std::fs::write(&path, "[[models]]\nprovider = \"anthropic\"\n").unwrap();
        let loaded = PriceList::load(&path);
        let OverrideRead::Refused(why) = &loaded.override_read else {
            panic!("{:?}", loaded.override_read)
        };
        assert!(why.contains("not a price list"), "{why}");
        assert_eq!(
            loaded.list.models().len(),
            PriceList::bundled().models().len()
        );
        // A link in its place is not followed.
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(matches!(
            PriceList::load(&path).override_read,
            OverrideRead::Refused(_)
        ));
        // Nor is a file too big read.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![b'#'; MAX_OVERRIDE_BYTES as usize + 1]).unwrap();
        let OverrideRead::Refused(why) = PriceList::load(&path).override_read else {
            panic!("read")
        };
        assert!(why.contains("larger than"), "{why}");
    }

    #[test]
    fn a_list_with_a_rate_a_name_or_a_provider_it_cannot_take_is_refused_whole() {
        let model = |fields: &str| {
            format!("[providers.anthropic]\n[[models]]\nprovider = \"anthropic\"\n{fields}\n")
        };
        assert!(refused(&model("id = \"m\"\ninput = -1.0\noutput = 1.0")).contains("rate"));
        assert!(refused(&model("id = \"m\"\ninput = inf\noutput = 1.0")).contains("rate"));
        assert!(refused(&model("id = \"m\"\ninput = 1.0\noutput = 1e9")).contains("rate"));
        assert!(refused(&model("id = \"m x\"\ninput = 1.0\noutput = 1.0")).contains("name"));
        assert!(refused(&model("id = \"m\u{202E}\"\ninput = 1.0\noutput = 1.0")).contains("name"));
        assert!(
            refused(&model("id = \"m\"\ninput = 1.0\noutput = 1.0\nmore = 1"))
                .contains("not a price list")
        );
        let twice = model("id = \"m\"\ninput = 1.0\noutput = 1.0")
            + "[[models]]\nprovider = \"anthropic\"\nid = \"M\"\ninput = 1.0\noutput = 1.0\n";
        assert!(refused(&twice).contains("twice"));
        let undeclared = "[[models]]\nprovider = \"nous\"\nid = \"m\"\ninput = 1.0\noutput = 1.0\n";
        assert!(refused(undeclared).contains("does not name"));
        let included = "[providers.sub]\nincluded = true\n[[models]]\nprovider = \"sub\"\nid = \"m\"\ninput = 1.0\noutput = 1.0\n";
        assert!(refused(included).contains("subscription"));
        let clash = "[providers.a]\naliases = [\"x\"]\n[providers.b]\naliases = [\"X\"]\n";
        assert!(refused(clash).contains("both"));
    }

    #[test]
    fn a_date_suffix_is_only_a_date() {
        assert_eq!(
            without_date("claude-haiku-4-5-20251001"),
            "claude-haiku-4-5"
        );
        assert_eq!(without_date("gpt-4o-2024-08-06"), "gpt-4o");
        assert_eq!(without_date("gpt-4o"), "gpt-4o");
        assert_eq!(without_date("model-2024"), "model-2024");
        assert_eq!(without_date("m-2024-8-06"), "m-2024-8-06");
        assert_eq!(without_date("-20251001"), "");
    }
}
