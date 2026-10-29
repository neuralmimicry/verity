//! Isolated numeric evaluation and immutable outcome evidence. Gail retains
//! model qualification and routing; a Verity report grants no execution rights.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use nm_workflow_core::{
    ApiError, App, Evaluation, EvidenceState, Result, SourceRef, Value, digest, json, now, require,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Held-out outputs are data supplied by the measuring adapter, not proof of
/// candidate isolation. Reports retain that limitation and exact dataset digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumericRow {
    pub group: String,
    pub feature_at: i64,
    pub decision_at: i64,
    pub observed_at: i64,
    pub prediction: f64,
    pub baseline: f64,
    pub observed: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumericEvaluation {
    pub id: String,
    pub candidate_digest: String,
    pub baseline_digest: String,
    pub feature_digest: String,
    pub task: String,
    pub domain: String,
    pub source: SourceRef,
    pub training_groups: Vec<String>,
    pub rows: Vec<NumericRow>,
    pub fixture_only: bool,
    pub expires_at: i64,
}
/// Fixed policy is versioned with the evaluator. Changing it changes the policy
/// digest; callers cannot lower thresholds after observing candidate results.
pub const POLICY: &str = "numeric-mae-v1:min_rows=30:min_groups=3:relative_mae<=0.95";
/// A retained historical manifest cannot remain active evidence after either
/// evaluator implementation or acceptance policy changes.
fn require_current_report(value: &Value) -> Result<()> {
    let report: Evaluation =
        serde_json::from_value(value.clone()).map_err(|_| ApiError::unavailable())?;
    if report.evaluator_digest != digest(&include_str!("lib.rs"))
        || report.policy_digest != digest(&POLICY)
    {
        return Err(ApiError(
            axum::http::StatusCode::GONE,
            "evaluation_revision_changed",
        ));
    }
    Ok(())
}
pub fn evaluate(input: &NumericEvaluation, tenant: &str, clock: i64) -> Result<Evaluation> {
    require(
        !input.rows.is_empty()
            && input.rows.len() <= 10000
            && input.training_groups.len() <= 10000
            && input.expires_at > clock
            && input.expires_at <= clock + 30 * 86400,
        "evaluation bounds",
    )?;
    input.source.validate(tenant, clock)?;
    require(
        !input.source.deleted && input.source.purposes.iter().any(|p| p == "evaluate"),
        "evaluation permission",
    )?;
    let training: BTreeSet<_> = input.training_groups.iter().collect();
    let mut groups = BTreeSet::new();
    let mut candidate = 0.0;
    let mut baseline = 0.0;
    for row in &input.rows {
        require(
            row.feature_at > 0
                && row.feature_at <= row.decision_at
                && row.decision_at < row.observed_at
                && row.observed_at <= clock
                && row.prediction.is_finite()
                && row.baseline.is_finite()
                && row.observed.is_finite()
                && !training.contains(&row.group)
                && nm_workflow_core::identifier(&row.group),
            "heldout leakage or invalid row",
        )?;
        groups.insert(&row.group);
        candidate += (row.prediction - row.observed).abs();
        baseline += (row.baseline - row.observed).abs();
    }
    let count = input.rows.len();
    candidate /= count as f64;
    baseline /= count as f64;
    require(
        candidate.is_finite() && baseline.is_finite(),
        "metric overflow",
    )?;
    let passed = count >= 30 && groups.len() >= 3 && baseline > 0.0 && candidate <= 0.95 * baseline;
    let state = if input.fixture_only {
        EvidenceState::FixtureOnly
    } else if passed {
        EvidenceState::Passed
    } else {
        EvidenceState::Failed
    };
    let report=Evaluation {
        schema_version:1,id:input.id.clone(),candidate_digest:input.candidate_digest.clone(),
        baseline_digest:input.baseline_digest.clone(),dataset_digest:digest(&input.rows),
        evaluator_digest:digest(&include_str!("lib.rs")),policy_digest:digest(&POLICY),
        feature_digest:input.feature_digest.clone(),task:input.task.clone(),tenant:tenant.into(),
        domain:input.domain.clone(),state,fixture_only:input.fixture_only,sample_count:count,
        metrics:BTreeMap::from([("mae".into(),candidate),("baseline_mae".into(),baseline),("groups".into(),groups.len() as f64)]),
        limitations:vec!["Adapter-supplied held-out predictions; adapter isolation and source accuracy require separate acceptance.".into(),
            "MAE comparison does not qualify prediction intervals, causal effects or other domains.".into()],
        created_at:clock,expires_at:input.expires_at,
    };
    report.validate(tenant, clock)?;
    Ok(report)
}
async fn run(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<NumericEvaluation>,
) -> Result<Json<Value>> {
    let actor = app.authorize(&headers, "control").await?;
    let source = app.source(&actor, &input.source, "evaluate").await?;
    require(source.version == input.source.version, "source version")?;
    // A repeated ID returns its exact original evidence; changing the request
    // conflicts. Never recompute with a fresh clock under an old qualification.
    let request_digest = digest(&input);
    if let Ok(previous) = app.store.get(&actor.tenant, "evaluation", &input.id).await {
        if previous["owner"] != actor.principal || previous["request_digest"] != request_digest {
            return Err(ApiError::conflict());
        }
        require_current_report(&previous["report"])?;
        return Ok(Json(previous["report"].clone()));
    }
    let permit = app
        .cpu_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::unavailable())?;
    let tenant = actor.tenant.clone();
    let report = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        evaluate(&input, &tenant, now())
    })
    .await
    .map_err(|_| ApiError::unavailable())??;
    let value = json!({"owner":actor.principal,"request_digest":request_digest,"report":report,"source":source});
    app.store
        .insert(
            &actor.tenant,
            "evaluation",
            &report.id,
            &actor.principal,
            &value,
        )
        .await?;
    Ok(Json(json!(report)))
}
async fn report(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>> {
    let actor = app.authorize(&headers, "observe").await?;
    let record = app.store.get(&actor.tenant, "evaluation", &id).await?;
    if record["owner"] != actor.principal {
        return Err(ApiError::forbidden());
    }
    let source: SourceRef =
        serde_json::from_value(record["source"].clone()).map_err(|_| ApiError::unavailable())?;
    app.source(&actor, &source, "evaluate").await?;
    require_current_report(&record["report"])?;
    Ok(Json(record["report"].clone()))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub id: String,
    pub work_id: String,
    pub prediction_id: String,
    pub metric: String,
    pub unit: String,
    pub observed: f64,
    pub measured_at: i64,
    pub source: SourceRef,
    pub confounders: Vec<String>,
}
async fn outcome(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Outcome>,
) -> Result<Json<Value>> {
    let actor = app.authorize(&headers, "use").await?;
    input.source.validate(&actor.tenant, now())?;
    let source = app.source(&actor, &input.source, "outcome").await?;
    require(source.version == input.source.version, "source version")?;
    require(
        input.source.permits(&actor, "outcome", now())
            && input.observed.is_finite()
            && input.measured_at > 0
            && input.measured_at <= now()
            && nm_workflow_core::identifier(&input.id)
            && !input.unit.is_empty(),
        "observed outcome",
    )?;
    let value = json!({"owner":actor.principal,"outcome":input});
    app.store
        .insert(
            &actor.tenant,
            "outcome",
            &input.id,
            &actor.principal,
            &value,
        )
        .await?;
    Ok(Json(value))
}
async fn capabilities(State(app): State<App>, headers: HeaderMap) -> Result<Json<Value>> {
    app.authorize(&headers, "observe").await?;
    Ok(Json(
        json!({"numeric_evaluation":"implemented","outcomes":"implemented","model_promotion":"gail_owned","policy":POLICY,"candidate_isolation":"adapter_owned"}),
    ))
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/v1/evaluations", post(run))
        .route("/v1/evaluations/{id}", get(report))
        .route("/v1/outcomes", post(outcome))
        .route("/v1/capabilities", get(capabilities))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> NumericEvaluation {
        NumericEvaluation {
            id: "e1".into(),
            candidate_digest: "a".repeat(64),
            baseline_digest: "b".repeat(64),
            feature_digest: "c".repeat(64),
            task: "compute_demand".into(),
            domain: "capacity".into(),
            source: SourceRef {
                source_id: "tracey".into(),
                object_id: "measurements".into(),
                version: "v1".into(),
                tenant: "t".into(),
                readers: vec!["alice".into()],
                purposes: vec!["evaluate".into()],
                observed_at: 1,
                access_expires_at: 200,
                deleted: false,
                training_permitted: false,
            },
            training_groups: vec!["training".into()],
            rows: (0..30)
                .map(|i| NumericRow {
                    group: format!("heldout-{}", i % 3),
                    feature_at: 1,
                    decision_at: 2,
                    observed_at: 3,
                    prediction: 9.0,
                    baseline: 5.0,
                    observed: 10.0,
                })
                .collect(),
            fixture_only: false,
            expires_at: 150,
        }
    }
    #[test]
    fn comparison_and_insufficient_support() {
        let mut i = input();
        assert_eq!(evaluate(&i, "t", 100).unwrap().state, EvidenceState::Passed);
        i.rows.truncate(2);
        assert_eq!(evaluate(&i, "t", 100).unwrap().state, EvidenceState::Failed);
    }
    #[test]
    fn evaluator_or_policy_changes_invalidate_retained_active_evidence() {
        let mut report = json!(evaluate(&input(), "t", 100).unwrap());
        assert!(require_current_report(&report).is_ok());
        report["evaluator_digest"] = json!("0".repeat(64));
        assert!(require_current_report(&report).is_err());
        report = json!(evaluate(&input(), "t", 100).unwrap());
        report["policy_digest"] = json!("0".repeat(64));
        assert!(require_current_report(&report).is_err());
    }
    #[test]
    fn fixtures_cannot_qualify() {
        let mut i = input();
        i.fixture_only = true;
        assert_eq!(
            evaluate(&i, "t", 100).unwrap().state,
            EvidenceState::FixtureOnly
        );
    }
    #[test]
    fn time_and_group_leakage_fail() {
        let mut i = input();
        i.rows[0].feature_at = 4;
        assert!(evaluate(&i, "t", 100).is_err());
        i = input();
        i.rows[0].group = "training".into();
        assert!(evaluate(&i, "t", 100).is_err());
        i = input();
        i.rows[0].prediction = f64::NAN;
        assert!(evaluate(&i, "t", 100).is_err());
    }
}
