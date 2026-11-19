//! `enclos prices`: the price list `enclos usage` estimates cost from
//! (issue #343, design §11, Usage), and a model's price in it.

use std::io::Write;

use clap::Args;
use serde::Serialize;

use enclos::engine::Engine;
use enclos::error::{Error, Result, exit};
use enclos::pricing::{ModelPrice, ModelProvider, Origin, OverrideRead, Price, PriceList};

#[derive(Args)]
pub struct PricesArgs {
    /// A model, as a runtime names it, to show the price of. Without it, what the list holds.
    model: Option<String>,
    /// The model provider that serves the model, as the runtime names it, such as anthropic or openai-codex.
    #[arg(long)]
    model_provider: Option<String>,
}

#[derive(Serialize)]
struct ModelProviderRow<'a> {
    #[serde(flatten)]
    model_provider: &'a ModelProvider,
    models: usize,
}

#[derive(Serialize)]
struct ListView<'a> {
    model_providers: Vec<ModelProviderRow<'a>>,
    models: usize,
    override_file: String,
    override_read: &'a OverrideRead,
}

#[derive(Serialize)]
#[serde(tag = "price", rename_all = "snake_case")]
enum Found<'a> {
    Rates {
        entry: &'a ModelPrice,
    },
    Included {
        /// The subscription the model was asked of, as the list names it.
        subscription: &'a ModelProvider,
        /// The rates its tokens are priced at, as if paid; none: no list
        /// price, so what they would cost is unknown.
        list: Option<&'a ModelPrice>,
    },
    Unknown,
}

impl<'a> Found<'a> {
    fn of(list: &'a PriceList, model_provider: Option<&str>, model: &str) -> Found<'a> {
        match list.find(model_provider, Some(model)) {
            Price::Rates(entry) => Found::Rates { entry },
            Price::Included(subscription) => Found::Included {
                subscription,
                list: list.list_price(subscription, Some(model)),
            },
            Price::Unknown => Found::Unknown,
        }
    }
}

#[derive(Serialize)]
struct ModelView<'a> {
    model: &'a str,
    model_provider: Option<&'a str>,
    #[serde(flatten)]
    found: Found<'a>,
    override_file: String,
    override_read: &'a OverrideRead,
}

pub fn run(engine: &Engine, args: PricesArgs) -> Result<u8> {
    let loaded = PriceList::load(&engine.prices_path());
    let override_file = loaded.override_file.display().to_string();
    match &args.model {
        None => {
            let view = ListView {
                model_providers: loaded
                    .list
                    .model_providers()
                    .map(|p| ModelProviderRow {
                        model_provider: p,
                        models: loaded
                            .list
                            .models()
                            .iter()
                            .filter(|m| m.model_provider == p.name)
                            .count(),
                    })
                    .collect(),
                models: loaded.list.models().len(),
                override_file,
                override_read: &loaded.override_read,
            };
            if super::output::json() {
                return json(&view);
            }
            // A reader that left ends this by SIGPIPE, as for `status`.
            let _ = print_list(&mut std::io::stdout().lock(), &view, &loaded.list);
        }
        Some(model) => {
            let found = Found::of(&loaded.list, args.model_provider.as_deref(), model);
            let view = ModelView {
                model,
                model_provider: args.model_provider.as_deref(),
                found,
                override_file,
                override_read: &loaded.override_read,
            };
            if super::output::json() {
                return json(&view);
            }
            let _ = print_model(&mut std::io::stdout().lock(), &view);
        }
    }
    Ok(exit::OK)
}

fn json(view: &impl Serialize) -> Result<u8> {
    let shown = serde_json::to_value(view).map_err(|source| Error::Json {
        what: "the prices",
        source,
    })?;
    super::output::emit(&shown);
    Ok(exit::OK)
}

fn print_list(out: &mut impl Write, view: &ListView<'_>, list: &PriceList) -> std::io::Result<()> {
    let priced = view.model_providers.iter().filter(|p| p.models > 0).count();
    writeln!(
        out,
        "enclos's price list, in US dollars per million tokens: {} models of {priced} model providers.",
        view.models
    )?;
    let generated: Vec<&str> = list
        .models()
        .iter()
        .filter(|m| m.origin == Origin::Bundled)
        .filter_map(|m| m.source.as_deref()?.strip_prefix("litellm@"))
        .collect();
    let mut commits: Vec<&str> = generated.clone();
    commits.sort_unstable();
    commits.dedup();
    let by_hand = list
        .models()
        .iter()
        .filter(|m| m.origin == Origin::Bundled)
        .count()
        - generated.len();
    writeln!(
        out,
        "Bundled with enclos: {} from LiteLLM ({}), {by_hand} kept by hand.",
        generated.len(),
        commits
            .iter()
            .map(|c| short(c))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(
        out,
        "{}",
        override_line(&view.override_file, view.override_read)
    )?;
    writeln!(out)?;
    let mut rows = vec![vec![
        "MODEL PROVIDER".to_owned(),
        "MODELS".to_owned(),
        "ALSO NAMED".to_owned(),
    ]];
    for p in &view.model_providers {
        rows.push(vec![
            p.model_provider.name.clone(),
            match (p.model_provider.included, &p.model_provider.priced_as) {
                (true, Some(other)) => format!("included, as {other}"),
                (true, None) => "included".to_owned(),
                (false, _) => p.models.to_string(),
            },
            p.model_provider.aliases.join(", "),
        ]);
    }
    let widths: Vec<usize> = (0..3)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    for r in &rows {
        let line = format!(
            "  {:<w0$}  {:>w1$}  {}",
            r[0],
            r[1],
            r[2],
            w0 = widths[0],
            w1 = widths[1]
        );
        writeln!(out, "{}", line.trim_end())?;
    }
    writeln!(
        out,
        "\n`included`: a subscription; its models' tokens count against its limits, not in dollars. `enclos prices <model> [--model-provider <name>]` shows a model's rates."
    )
}

fn print_model(out: &mut impl Write, view: &ModelView<'_>) -> std::io::Result<()> {
    let through = view
        .model_provider
        .map(|p| format!(" through {p}"))
        .unwrap_or_default();
    match &view.found {
        Found::Rates { entry } => print_rates(out, entry, &view.override_file),
        Found::Included { subscription, list } => {
            writeln!(
                out,
                "{} is a subscription: what {}{through} uses counts against its limits, not in dollars, so its cost is included.",
                subscription.name, view.model
            )?;
            match list {
                Some(entry) => {
                    writeln!(
                        out,
                        "Priced as if paid, to show how heavy an agent is, at the list price of"
                    )?;
                    print_rates(out, entry, &view.override_file)
                }
                None => writeln!(
                    out,
                    "It has no list price in the price list: what it would cost if paid is unknown."
                ),
            }
        }
        Found::Unknown => {
            writeln!(
                out,
                "No price for {}{through}: its cost shows as ? in `enclos usage`.",
                view.model
            )?;
            writeln!(
                out,
                "Add one to {}, in the format of the bundled list (`[model_providers.<name>]`, then `[[models]]` with model_provider, id, input and output).",
                view.override_file
            )?;
            match view.override_read {
                OverrideRead::Refused(_) => {
                    writeln!(
                        out,
                        "{}",
                        override_line(&view.override_file, view.override_read)
                    )
                }
                _ => Ok(()),
            }
        }
    }
}

/// A model's rates, per million tokens, and where they came from.
fn print_rates(
    out: &mut impl Write,
    entry: &ModelPrice,
    override_file: &str,
) -> std::io::Result<()> {
    let r = &entry.rates;
    let mut parts = vec![
        format!("input {}", rate(r.input)),
        format!("output {}", rate(r.output)),
    ];
    parts.push(format!(
        "cache read {}",
        r.cache_read
            .map(rate)
            .unwrap_or_else(|| format!("{} (as input)", rate(r.input)))
    ));
    parts.push(format!(
        "cache write {}",
        r.cache_write
            .map(rate)
            .unwrap_or_else(|| format!("{} (as input)", rate(r.input)))
    ));
    writeln!(
        out,
        "{} of {}: {} per million tokens.",
        entry.id,
        entry.model_provider,
        parts.join(", ")
    )?;
    let from = entry
        .source
        .as_deref()
        .map(|s| match s.strip_prefix("litellm@") {
            Some(commit) => format!("LiteLLM {}", short(commit)),
            None => s.to_owned(),
        })
        .unwrap_or_else(|| "no source given".into());
    let origin = match entry.origin {
        Origin::Bundled => "the list bundled with enclos".to_owned(),
        Origin::Override => override_file.to_owned(),
    };
    writeln!(out, "From {from}, in {origin}.")
}

fn override_line(file: &str, read: &OverrideRead) -> String {
    match read {
        OverrideRead::Absent => format!("Override: none ({file} would be read)."),
        OverrideRead::Read {
            models,
            model_providers,
        } => {
            format!("Override: {file}, {models} models and {model_providers} model providers.")
        }
        OverrideRead::Refused(why) => {
            format!("Override: {file} was not read ({why}); the bundled list is used alone.")
        }
    }
}

/// A commit's first 12 characters.
fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

/// A rate per million tokens: `$4.00`, `$0.075`, at most six decimals.
fn rate(r: f64) -> String {
    let text = format!("{r:.6}");
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let fraction = fraction.trim_end_matches('0');
    format!("${whole}.{fraction:0<2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown_model(model: &str, model_provider: Option<&str>, list: &PriceList) -> String {
        let found = Found::of(list, model_provider, model);
        let view = ModelView {
            model,
            model_provider,
            found,
            override_file: "/c/enclos/prices.toml".into(),
            override_read: &OverrideRead::Absent,
        };
        let mut out = Vec::new();
        print_model(&mut out, &view).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_rate_reads_in_dollars_with_cents_at_least() {
        assert_eq!(rate(4.0), "$4.00");
        assert_eq!(rate(0.2), "$0.20");
        assert_eq!(rate(0.075), "$0.075");
        assert_eq!(rate(0.0000004), "$0.00");
        assert_eq!(rate(1_000_000.0), "$1000000.00");
    }

    #[test]
    fn a_subscription_in_json_keeps_the_name_asked_and_its_list_price_apart() {
        let list = PriceList::bundled();
        let view = ModelView {
            model: "gpt-5.5",
            model_provider: Some("chatgpt-login"),
            found: Found::of(&list, Some("openai-codex"), "gpt-5.5"),
            override_file: "/c/enclos/prices.toml".into(),
            override_read: &OverrideRead::Absent,
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["price"], "included");
        assert_eq!(json["model_provider"], "chatgpt-login");
        assert_eq!(json["subscription"]["name"], "openai-codex");
        assert_eq!(json["list"]["model_provider"], "openai");
    }

    #[test]
    fn a_model_shows_its_rates_and_where_they_came_from_a_subscription_and_an_unknown_say_so() {
        let list = PriceList::bundled();
        let opus = shown_model("claude-opus-5-5", Some("anthropic"), &list);
        assert!(
            opus.starts_with("claude-opus-5-5 of anthropic: input $"),
            "{opus}"
        );
        assert!(opus.contains("From LiteLLM "), "{opus}");
        assert!(opus.contains("the list bundled with enclos"), "{opus}");
        let codex = shown_model("gpt-5.5", Some("openai-codex"), &list);
        assert!(
            codex.starts_with("openai-codex is a subscription"),
            "{codex}"
        );
        // And the list price it is priced at, as if paid: OpenAI's.
        assert!(codex.contains("Priced as if paid"), "{codex}");
        assert!(codex.contains("gpt-5.5 of openai: input $"), "{codex}");
        let unknown = shown_model("hermes-9", Some("nous"), &list);
        assert!(
            unknown.starts_with("No price for hermes-9 through nous"),
            "{unknown}"
        );
        assert!(unknown.contains("/c/enclos/prices.toml"), "{unknown}");
    }

    #[test]
    fn the_list_says_how_many_models_each_model_provider_has_and_which_are_subscriptions() {
        let list = PriceList::bundled();
        let read = OverrideRead::Refused("is not a price list".into());
        let view = ListView {
            model_providers: list
                .model_providers()
                .map(|p| ModelProviderRow {
                    model_provider: p,
                    models: list
                        .models()
                        .iter()
                        .filter(|m| m.model_provider == p.name)
                        .count(),
                })
                .collect(),
            models: list.models().len(),
            override_file: "/c/enclos/prices.toml".into(),
            override_read: &read,
        };
        let mut out = Vec::new();
        print_list(&mut out, &view, &list).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Bundled with enclos: "), "{text}");
        assert!(text.contains("0 kept by hand"), "{text}");
        assert!(
            text.contains("/c/enclos/prices.toml was not read (is not a price list)"),
            "{text}"
        );
        let codex = text
            .lines()
            .find(|l| l.trim_start().starts_with("openai-codex"))
            .unwrap();
        assert!(codex.contains("included"), "{codex}");
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["override_read"]["refused"], "is not a price list");
        assert!(json["model_providers"][0]["name"].is_string());
    }
}
