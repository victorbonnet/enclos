//! Runtime-owned scheduled work, managed through a live channel-plugin request.
use serde::{Deserialize, Serialize};

use crate::{ConversationId, MessageId};

pub const PAGE_SIZE: usize = 25;
pub const MAX_PROMPT_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoutineSchedule {
    Cron { expression: String },
    Interval { minutes: u64 },
    Once { at: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub prompt: String,
    pub schedule: RoutineSchedule,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ConversationId>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Absent means the runtime defaults; an empty list deliberately selects no tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolsets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(default)]
    pub script_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineSummary {
    pub id: String,
    /// Opaque revision of editable fields, unaffected by scheduled execution.
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub schedule: RoutineSchedule,
    pub enabled: bool,
    pub prompt_preview: String,
    pub delivery_label: String,
    /// Jobs belonging to another channel can be shown without permitting changes.
    pub editable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Routine {
    #[serde(flatten)]
    pub summary: RoutineSummary,
    pub definition: RoutineDefinition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineChoice {
    pub id: String,
    pub label: String,
}

/// A model's provider travels with its id so a picker cannot combine mismatched overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineModelChoice {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineOptions {
    /// The runtime's effective timezone, not a per-job override.
    pub timezone: String,
    /// Supported live controls. Absent preserves the preceding contract;
    /// an explicit empty list exposes a read-only inventory. Unknown names
    /// confer no ability in an older app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub skills: Vec<RoutineChoice>,
    #[serde(default)]
    pub models: Vec<RoutineModelChoice>,
    #[serde(default)]
    pub toolsets: Vec<RoutineChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RoutineRequest {
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    },
    Get {
        routine: String,
    },
    Create {
        definition: RoutineDefinition,
    },
    Update {
        routine: String,
        revision: String,
        definition: RoutineDefinition,
    },
    Delete {
        routine: String,
        revision: String,
    },
    SetEnabled {
        routine: String,
        revision: String,
        enabled: bool,
    },
    Run {
        routine: String,
        revision: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum RoutineResult {
    List {
        routines: Vec<RoutineSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<String>,
        options: RoutineOptions,
        /// Supplied by the bridge, never trusted from a plugin.
        #[serde(default)]
        deliveries: Vec<RoutineChoice>,
        #[serde(default)]
        deliveries_limited: bool,
    },
    Routine {
        routine: Box<Routine>,
    },
    Deleted {
        routine: String,
    },
    /// The runtime accepted a run request; this does not mean execution completed.
    Run {
        routine: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineReply {
    pub of: MessageId,
    #[serde(flatten)]
    pub result: RoutineResult,
}

fn text(value: &str, maximum: usize, empty: bool) -> Result<(), String> {
    if (!empty && value.trim().is_empty()) || value.len() > maximum || value.contains('\0') {
        return Err("A routine field is empty, too long, or contains a null character.".into());
    }
    Ok(())
}

impl RoutineDefinition {
    pub fn validate(&self) -> Result<(), String> {
        let has_other_work = self.script_only
            || !self.skills.is_empty()
            || self.script.as_deref().is_some_and(|s| !s.trim().is_empty());
        text(&self.prompt, MAX_PROMPT_BYTES, has_other_work)?;
        for value in [
            &self.name,
            &self.model,
            &self.provider,
            &self.script,
            &self.working_directory,
        ]
        .into_iter()
        .flatten()
        {
            text(value, 512, true)?;
        }
        for values in [&self.skills, self.toolsets.as_ref().unwrap_or(&Vec::new())] {
            if values.len() > 32 {
                return Err("A routine may select at most 32 skills or toolsets.".into());
            }
            for value in values {
                text(value, 128, false)?;
            }
        }
        self.schedule.validate()?;
        if self.script_only && self.script.as_deref().is_none_or(|s| s.trim().is_empty()) {
            return Err("A script-only routine needs a script.".into());
        }
        Ok(())
    }
}

impl RoutineSchedule {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Cron { expression } => text(expression, 128, false),
            Self::Once { at } => text(at, 128, false),
            Self::Interval { minutes } if *minutes > 0 && *minutes <= 525600 => Ok(()),
            Self::Interval { .. } => {
                Err("A repeat interval must be between one minute and one year.".into())
            }
        }
    }
}

impl RoutineRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::List { cursor } => {
                if let Some(value) = cursor {
                    text(value, 128, false)?;
                }
            }
            Self::Get { routine } => text(routine, 128, false)?,
            Self::Create { definition } => definition.validate()?,
            Self::Update {
                routine,
                revision,
                definition,
            } => {
                text(routine, 128, false)?;
                text(revision, 128, false)?;
                definition.validate()?;
            }
            Self::Delete { routine, revision }
            | Self::SetEnabled {
                routine, revision, ..
            }
            | Self::Run { routine, revision } => {
                text(routine, 128, false)?;
                text(revision, 128, false)?;
            }
        }
        Ok(())
    }

    pub fn definition(&self) -> Option<&RoutineDefinition> {
        match self {
            Self::Create { definition } | Self::Update { definition, .. } => Some(definition),
            _ => None,
        }
    }

    pub fn accepts(&self, result: &RoutineResult) -> bool {
        match (self, result) {
            (Self::List { .. }, RoutineResult::List { .. }) => true,
            (Self::Create { .. }, RoutineResult::Routine { .. }) => true,
            (
                Self::Get { routine }
                | Self::Update { routine, .. }
                | Self::SetEnabled { routine, .. },
                RoutineResult::Routine { routine: found },
            ) => routine == &found.summary.id,
            (Self::Delete { routine, .. }, RoutineResult::Deleted { routine: found })
            | (Self::Run { routine, .. }, RoutineResult::Run { routine: found }) => {
                routine == found
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_requests_preserve_explicit_no_tools_and_script_mode() {
        let request: RoutineRequest = serde_json::from_str(r#"{"action":"create","definition":{"prompt":"","schedule":{"kind":"interval","minutes":5},"toolsets":[],"script_only":true,"script":"morning.py"}}"#).unwrap();
        request.validate().unwrap();
        let definition = request.definition().unwrap();
        assert_eq!(definition.toolsets, Some(vec![]));
        assert!(serde_json::to_value(request).unwrap()["definition"]["delivery"].is_null());
    }

    #[test]
    fn empty_or_oversized_work_is_rejected_before_forwarding() {
        let mut request: RoutineRequest = serde_json::from_str(r#"{"action":"create","definition":{"prompt":"hello","schedule":{"kind":"interval","minutes":0}}}"#).unwrap();
        assert!(request.validate().is_err());
        if let RoutineRequest::Create { definition } = &mut request {
            definition.schedule = RoutineSchedule::Interval { minutes: 1 };
            definition.prompt = "a".repeat(MAX_PROMPT_BYTES + 1);
        }
        assert!(request.validate().is_err());
    }

    #[test]
    fn model_choices_keep_provider_and_legacy_choices_remain_readable() {
        let options: RoutineOptions = serde_json::from_value(serde_json::json!({
            "timezone":"UTC", "models":[
                {"id":"same-model", "label":"Provider A / same-model", "provider":"provider-a"},
                {"id":"same-model", "label":"Provider B / same-model", "provider":"provider-b"},
                {"id":"legacy", "label":"legacy"}
            ]
        }))
        .unwrap();
        assert_eq!(options.models[0].provider.as_deref(), Some("provider-a"));
        assert_eq!(options.models[1].provider.as_deref(), Some("provider-b"));
        assert_eq!(options.models[2].provider, None);
        assert_eq!(options.operations, None);
    }

    #[test]
    fn an_explicit_read_only_operation_set_survives_the_wire() {
        let options: RoutineOptions =
            serde_json::from_value(serde_json::json!({"timezone":"UTC", "operations":[]})).unwrap();
        assert_eq!(options.operations, Some(vec![]));
        assert_eq!(
            serde_json::to_value(options).unwrap()["operations"],
            serde_json::json!([])
        );
    }
}
