//! Task-specific evaluation envelopes. Qualification binds exact artefacts,
//! data, evaluator, scope, policy and expiry. Fixtures cannot qualify production.
use crate::{Result, require};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Unavailable,
    NotRun,
    FixtureOnly,
    Failed,
    Passed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub schema_version: u32,
    pub id: String,
    pub candidate_digest: String,
    pub baseline_digest: String,
    pub dataset_digest: String,
    pub evaluator_digest: String,
    pub policy_digest: String,
    pub feature_digest: String,
    pub task: String,
    pub tenant: String,
    pub domain: String,
    pub state: EvidenceState,
    pub fixture_only: bool,
    pub sample_count: usize,
    pub metrics: BTreeMap<String, f64>,
    pub limitations: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
}
pub fn valid_digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
impl Evaluation {
    pub fn validate(&self, tenant: &str, now: i64) -> Result<()> {
        require(
            self.schema_version == 1
                && self.tenant == tenant
                && crate::identifier(&self.id)
                && crate::identifier(&self.task)
                && crate::identifier(&self.domain)
                && [
                    &self.candidate_digest,
                    &self.baseline_digest,
                    &self.dataset_digest,
                    &self.evaluator_digest,
                    &self.policy_digest,
                    &self.feature_digest,
                ]
                .iter()
                .all(|d| valid_digest(d))
                && self.created_at > 0
                && self.created_at <= now
                && self.expires_at > self.created_at
                && self.metrics.values().all(|v| v.is_finite())
                && (!self.fixture_only || self.state != EvidenceState::Passed)
                && (self.state != EvidenceState::Passed || self.sample_count > 0),
            "invalid evaluation",
        )
    }
    // Keep every qualification scope explicit at this cross-service boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn qualifies(
        &self,
        candidate: &str,
        dataset: &str,
        features: &str,
        task: &str,
        tenant: &str,
        domain: &str,
        now: i64,
    ) -> bool {
        self.validate(tenant, now).is_ok()
            && self.state == EvidenceState::Passed
            && !self.fixture_only
            && self.expires_at > now
            && self.candidate_digest == candidate
            && self.dataset_digest == dataset
            && self.feature_digest == features
            && self.task == task
            && self.domain == domain
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Evaluation {
        Evaluation {
            schema_version: 1,
            id: "eval-1".into(),
            candidate_digest: "a".repeat(64),
            baseline_digest: "b".repeat(64),
            dataset_digest: "c".repeat(64),
            evaluator_digest: "d".repeat(64),
            policy_digest: "e".repeat(64),
            feature_digest: "f".repeat(64),
            task: "compute_demand".into(),
            tenant: "t".into(),
            domain: "capacity".into(),
            state: EvidenceState::Passed,
            fixture_only: false,
            sample_count: 100,
            metrics: BTreeMap::new(),
            limitations: vec![],
            created_at: 10,
            expires_at: 100,
        }
    }
    #[test]
    fn changing_any_bound_artifact_invalidates_evidence() {
        let e = example();
        assert!(e.qualifies(
            &"a".repeat(64),
            &"c".repeat(64),
            &"f".repeat(64),
            "compute_demand",
            "t",
            "capacity",
            20
        ));
        assert!(!e.qualifies(
            &"b".repeat(64),
            &"c".repeat(64),
            &"f".repeat(64),
            "compute_demand",
            "t",
            "capacity",
            20
        ));
        assert!(!e.qualifies(
            &"a".repeat(64),
            &"d".repeat(64),
            &"f".repeat(64),
            "compute_demand",
            "t",
            "capacity",
            20
        ));
        assert!(!e.qualifies(
            &"a".repeat(64),
            &"c".repeat(64),
            &"f".repeat(64),
            "compute_demand",
            "t",
            "capacity",
            100
        ));
        let mut fixture = e;
        fixture.fixture_only = true;
        assert!(fixture.validate("t", 20).is_err());
    }
}
