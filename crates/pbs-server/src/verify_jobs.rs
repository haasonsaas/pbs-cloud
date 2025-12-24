use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VerificationJobConfig {
    pub id: String,
    pub store: String,
    pub ignore_verified: Option<bool>,
    pub outdated_after: Option<i64>,
    pub comment: Option<String>,
    pub schedule: Option<String>,
    pub ns: Option<String>,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct VerificationJobConfigUpdater {
    pub store: Option<String>,
    pub ignore_verified: Option<bool>,
    pub outdated_after: Option<i64>,
    pub comment: Option<String>,
    pub schedule: Option<String>,
    pub ns: Option<String>,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeletableProperty {
    IgnoreVerified,
    Comment,
    Schedule,
    OutdatedAfter,
    Ns,
    MaxDepth,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct VerificationJobState {
    pub id: String,
    pub last_run_upid: Option<String>,
    pub last_run_state: Option<String>,
    pub last_run_endtime: Option<i64>,
}

impl VerificationJobState {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            last_run_upid: None,
            last_run_state: None,
            last_run_endtime: None,
        }
    }
}

impl VerificationJobConfig {
    pub fn apply_update(
        &mut self,
        update: VerificationJobConfigUpdater,
        delete: Option<Vec<DeletableProperty>>,
    ) {
        if let Some(delete) = delete {
            for prop in delete {
                match prop {
                    DeletableProperty::IgnoreVerified => self.ignore_verified = None,
                    DeletableProperty::Comment => self.comment = None,
                    DeletableProperty::Schedule => self.schedule = None,
                    DeletableProperty::OutdatedAfter => self.outdated_after = None,
                    DeletableProperty::Ns => self.ns = None,
                    DeletableProperty::MaxDepth => self.max_depth = None,
                }
            }
        }

        if let Some(store) = update.store {
            self.store = store;
        }
        if update.ignore_verified.is_some() {
            self.ignore_verified = update.ignore_verified;
        }
        if update.outdated_after.is_some() {
            self.outdated_after = update.outdated_after;
        }
        if let Some(comment) = update.comment {
            let trimmed = comment.trim().to_string();
            if trimmed.is_empty() {
                self.comment = None;
            } else {
                self.comment = Some(trimmed);
            }
        }
        if let Some(schedule) = update.schedule {
            let trimmed = schedule.trim().to_string();
            if trimmed.is_empty() {
                self.schedule = None;
            } else {
                self.schedule = Some(trimmed);
            }
        }
        if let Some(ns) = update.ns {
            let trimmed = ns.trim().to_string();
            if trimmed.is_empty() {
                self.ns = None;
            } else {
                self.ns = Some(trimmed);
            }
        }
        if update.max_depth.is_some() {
            self.max_depth = update.max_depth;
        }
    }
}
