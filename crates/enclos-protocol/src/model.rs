//! An agent's model: its runtime's own setting, read and changed through
//! the agent's channel (`model` capability, issue #325). The runtime
//! keeps the setting and its catalogue of model providers and models; the bridge
//! only authorizes the host's person and checks what passes.
use serde::{Deserialize, Serialize};

use crate::MessageId;

/// The most providers an `options` result lists.
pub const MAX_PROVIDERS: usize = 100;
/// The most models a `models` result lists for one provider; a runtime
/// with more says so (`limited`) and the app takes a typed id.
pub const MAX_MODELS: usize = 300;
/// The most bytes of a provider's or a model's id, and of a revision.
pub const MAX_ID_BYTES: usize = 200;
/// The most bytes of a label.
pub const MAX_LABEL_BYTES: usize = 200;
/// The most bytes of what to do on the host to set a model provider up.
pub const MAX_SETUP_BYTES: usize = 500;
/// The most bytes of a plugin's `model.response` line, which both plugins
/// keep under by listing fewer models (`limited`) or refusing a read
/// (`unsupported`): under the bridge's 60 KiB device-message budget, with
/// room for the envelope the bridge adds.
pub const MAX_REPLY_BYTES: usize = 44 * 1024;

/// What a device asks of an agent's model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ModelRequest {
    /// The agent's model now, its revision, and the providers the runtime
    /// knows, without their models.
    Options,
    /// The models one provider offers.
    Models { provider: String },
    /// Make `provider`'s `model` the agent's model, for all its
    /// conversations, unless the setting changed since `revision`.
    Set {
        provider: String,
        model: String,
        revision: String,
    },
}

/// A provider and one of its models. The provider is absent when the
/// runtime's settings name only a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub model: String,
}

/// How a change of model takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelApply {
    /// On the agent's next turn, with no restart.
    Live,
    /// Once the runtime's service restarts, with every agent it serves.
    Restart,
    #[serde(other)]
    Unknown,
}

/// A model provider as the runtime lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvider {
    pub id: String,
    pub label: String,
    /// Whether the agent can use it now: false when the runtime has no
    /// login or secret for it, or its settings rule it out.
    pub usable: bool,
    /// Present exactly when it is not usable: what to do on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<String>,
}

/// One model of a provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelChoice {
    pub id: String,
    pub label: String,
}

/// What the runtime answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ModelResult {
    Options {
        /// None when the agent's settings name no model.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current: Option<ModelSelection>,
        /// Opaque: changes whenever the agent's model setting does.
        revision: String,
        applies: ModelApply,
        providers: Vec<ModelProvider>,
        /// Whether the runtime takes a model id its lists do not name.
        #[serde(default)]
        custom_models: bool,
    },
    Models {
        provider: String,
        models: Vec<ModelChoice>,
        /// The provider offers more than were listed.
        #[serde(default)]
        limited: bool,
    },
    Set {
        /// What the agent had, for the bridge's log.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous: Option<ModelSelection>,
        /// What the runtime saved, which may be the canonical form of the
        /// id asked for.
        current: ModelSelection,
        revision: String,
        applies: ModelApply,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelReply {
    pub of: MessageId,
    #[serde(flatten)]
    pub result: ModelResult,
}

/// Whether `value` can be shown: the runtime or a person chooses it, and
/// it reaches the bridge's log and a person's screen, so it is short, not
/// blank, and holds no control or hidden character.
fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !crate::visible::has_hidden(value, false)
}

fn valid_id(value: &str) -> bool {
    valid_text(value, MAX_ID_BYTES)
}

/// Whether no two of `ids` are the same: the app keys its rows by id.
fn distinct<'a>(ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::HashSet::new();
    ids.into_iter().all(|id| seen.insert(id))
}

impl ModelSelection {
    fn valid(&self) -> bool {
        valid_id(&self.model) && self.provider.as_deref().is_none_or(valid_id)
    }
}

impl ModelRequest {
    pub fn validate(&self) -> Result<(), String> {
        let ok = match self {
            ModelRequest::Options => true,
            ModelRequest::Models { provider } => valid_id(provider),
            ModelRequest::Set {
                provider,
                model,
                revision,
            } => valid_id(provider) && valid_id(model) && valid_id(revision),
        };
        if ok {
            Ok(())
        } else {
            Err("A provider, model or revision is empty, too long, or holds a control or hidden character.".into())
        }
    }

    /// Whether `result` is an answer to this request, within the bounds:
    /// the kind it asked for, the model provider it named, every id and
    /// label short and visible and no id twice, and a `setup` exactly for
    /// a model provider not usable.
    pub fn accepts(&self, result: &ModelResult) -> bool {
        match (self, result) {
            (
                ModelRequest::Options,
                ModelResult::Options {
                    current,
                    revision,
                    applies,
                    providers,
                    ..
                },
            ) => {
                *applies != ModelApply::Unknown
                    && valid_id(revision)
                    && current.as_ref().is_none_or(ModelSelection::valid)
                    && providers.len() <= MAX_PROVIDERS
                    && distinct(providers.iter().map(|p| p.id.as_str()))
                    && providers.iter().all(|p| {
                        valid_id(&p.id)
                            && valid_text(&p.label, MAX_LABEL_BYTES)
                            && p.usable == p.setup.is_none()
                            && p.setup
                                .as_deref()
                                .is_none_or(|s| valid_text(s, MAX_SETUP_BYTES))
                    })
            }
            (
                ModelRequest::Models { provider },
                ModelResult::Models {
                    provider: listed,
                    models,
                    ..
                },
            ) => {
                provider == listed
                    && models.len() <= MAX_MODELS
                    && distinct(models.iter().map(|m| m.id.as_str()))
                    && models
                        .iter()
                        .all(|m| valid_id(&m.id) && valid_text(&m.label, MAX_LABEL_BYTES))
            }
            (
                ModelRequest::Set { provider, .. },
                ModelResult::Set {
                    previous,
                    current,
                    revision,
                    applies,
                },
            ) => {
                *applies != ModelApply::Unknown
                    && valid_id(revision)
                    && current.valid()
                    // The runtime may write the model's id in its own form,
                    // never under another model provider.
                    && current.provider.as_deref() == Some(provider.as_str())
                    && previous.as_ref().is_none_or(ModelSelection::valid)
            }
            _ => false,
        }
    }
}

/// The model, then its model provider in brackets: a model id may itself
/// hold a `/` (`anthropic/x` through OpenRouter), so `provider/model` would
/// be ambiguous in the bridge's log.
impl std::fmt::Display for ModelSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.provider {
            Some(provider) => write!(f, "{} ({provider})", self.model),
            None => f.write_str(&self.model),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> ModelResult {
        ModelResult::Options {
            current: Some(ModelSelection {
                provider: Some("provider-a".into()),
                model: "model-1".into(),
            }),
            revision: "r1".into(),
            applies: ModelApply::Live,
            providers: vec![
                ModelProvider {
                    id: "provider-a".into(),
                    label: "Provider A".into(),
                    usable: true,
                    setup: None,
                },
                ModelProvider {
                    id: "provider-b".into(),
                    label: "Provider B".into(),
                    usable: false,
                    setup: Some("Log in on the host.".into()),
                },
            ],
            custom_models: true,
        }
    }

    #[test]
    fn requests_read_as_their_action() {
        let set: ModelRequest = serde_json::from_str(
            r#"{"action":"set","provider":"provider-a","model":"model-2","revision":"r1"}"#,
        )
        .unwrap();
        assert_eq!(
            set,
            ModelRequest::Set {
                provider: "provider-a".into(),
                model: "model-2".into(),
                revision: "r1".into()
            }
        );
        assert_eq!(
            serde_json::to_string(&ModelRequest::Options).unwrap(),
            r#"{"action":"options"}"#
        );
    }

    #[test]
    fn requests_with_hidden_or_blank_ids_are_refused() {
        for (provider, model) in [("", "m"), ("p", " "), ("p\u{202e}", "m"), ("p", "m\n")] {
            let request = ModelRequest::Set {
                provider: provider.into(),
                model: model.into(),
                revision: "r".into(),
            };
            assert!(request.validate().is_err(), "{provider:?} {model:?}");
        }
        let long = ModelRequest::Models {
            provider: "p".repeat(MAX_ID_BYTES + 1),
        };
        assert!(long.validate().is_err());
    }

    #[test]
    fn a_result_answers_only_its_own_request() {
        assert!(ModelRequest::Options.accepts(&options()));
        let models = ModelRequest::Models {
            provider: "provider-a".into(),
        };
        assert!(!models.accepts(&options()));
        let other = ModelResult::Models {
            provider: "provider-b".into(),
            models: vec![],
            limited: false,
        };
        assert!(!models.accepts(&other), "another provider's list");
    }

    #[test]
    fn results_out_of_bounds_are_refused() {
        let ModelResult::Options { providers, .. } = options() else {
            unreachable!()
        };
        let too_many = ModelResult::Options {
            current: None,
            revision: "r".into(),
            applies: ModelApply::Restart,
            providers: std::iter::repeat_n(providers[0].clone(), MAX_PROVIDERS + 1).collect(),
            custom_models: false,
        };
        assert!(!ModelRequest::Options.accepts(&too_many));
        let unknown_apply: ModelResult = serde_json::from_str(
            r#"{"result":"options","revision":"r","applies":"someday","providers":[]}"#,
        )
        .unwrap();
        assert!(!ModelRequest::Options.accepts(&unknown_apply));
        let hidden_label = ModelResult::Models {
            provider: "p".into(),
            models: vec![ModelChoice {
                id: "m".into(),
                label: "m\u{200b}".into(),
            }],
            limited: false,
        };
        assert!(
            !ModelRequest::Models {
                provider: "p".into()
            }
            .accepts(&hidden_label)
        );
    }

    #[test]
    fn duplicate_ids_and_a_setup_out_of_place_are_refused() {
        let ModelResult::Options {
            current,
            revision,
            applies,
            providers,
            custom_models,
        } = options()
        else {
            unreachable!()
        };
        let with = |providers: Vec<ModelProvider>| ModelResult::Options {
            current: current.clone(),
            revision: revision.clone(),
            applies,
            providers,
            custom_models,
        };
        let twice = vec![providers[0].clone(), providers[0].clone()];
        assert!(!ModelRequest::Options.accepts(&with(twice)));
        let mut usable_with_setup = providers.clone();
        usable_with_setup[0].setup = Some("Log in.".into());
        assert!(!ModelRequest::Options.accepts(&with(usable_with_setup)));
        let mut unusable_without = providers.clone();
        unusable_without[1].setup = None;
        assert!(!ModelRequest::Options.accepts(&with(unusable_without)));
        let models = ModelRequest::Models {
            provider: "p".into(),
        };
        let choice = ModelChoice {
            id: "m".into(),
            label: "M".into(),
        };
        let repeated = ModelResult::Models {
            provider: "p".into(),
            models: vec![choice.clone(), choice],
            limited: false,
        };
        assert!(!models.accepts(&repeated));
    }

    #[test]
    fn a_set_answered_under_another_provider_is_refused() {
        let set = ModelRequest::Set {
            provider: "provider-a".into(),
            model: "model-2".into(),
            revision: "r1".into(),
        };
        let answer = |provider: Option<&str>| ModelResult::Set {
            previous: None,
            current: ModelSelection {
                provider: provider.map(str::to_owned),
                model: "model-2-canonical".into(),
            },
            revision: "r2".into(),
            applies: ModelApply::Live,
        };
        assert!(set.accepts(&answer(Some("provider-a"))), "a canonical id");
        assert!(!set.accepts(&answer(Some("provider-b"))));
        assert!(!set.accepts(&answer(None)));
    }

    #[test]
    fn a_selection_shows_its_model_then_its_provider() {
        let with = ModelSelection {
            provider: Some("p".into()),
            model: "m".into(),
        };
        let without = ModelSelection {
            provider: None,
            model: "m".into(),
        };
        assert_eq!(with.to_string(), "m (p)");
        assert_eq!(without.to_string(), "m");
    }
}
