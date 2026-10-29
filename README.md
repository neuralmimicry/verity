# NeuralMimicry Verity

Shared evaluation contracts, isolated scoring and observed outcomes.

Verity is an evaluation library plus a dedicated worker process. nm-workflow-core contains the common source, identity and Evaluation v1 envelopes; all four products depend on this one implementation. The worker has its own database and CPU budget. Gail retains fitting, model registration, qualification and routing. No evaluation endpoint promotes a model.

POST /v1/evaluations runs the fixed numeric-mae-v1 evaluator. It compares adapter-supplied candidate and baseline outputs against observed labels, rejects nonfinite values, enforces feature_at <= decision_at < observed_at <= now, and rejects groups present in training_groups. Its versioned policy requires at least 30 rows and three held-out groups and candidate MAE <= 95% of a positive baseline MAE. Fixture runs always return fixture_only. Small or worse candidates return failed. This does not measure calibrated interval coverage or establish causal effects.

Each report binds candidate, baseline, dataset, feature schema, evaluator source and policy digests, scope, support, limitations and expiry. Identical request IDs replay the original report; changed requests conflict. GET /v1/evaluations/{id} restricts reports to their publishing actor and rechecks Relay source permission. POST /v1/outcomes records observed values with units, source, measurement time, work/prediction links and confounders. There is no model-estimate field that can silently become an observed label.

The evaluator trusts its measuring adapter to provide genuine held-out outputs and observations. A self-reported prediction set is not proof of candidate isolation. Existing Gail ELM, SFT, trading, Refiner and AARNN evaluators remain authoritative for their domains; automatic import/promotion from those evaluators is not enabled. A controlled adapter must bind their original evidence before adding a production qualification path.

The contracts distinguish unavailable, not_run, fixture_only, failed and passed. passed describes the declared task-specific comparison only; consumers must still enforce their own acceptance and deployment policies.

## Build and run

Rust 1.98.1 or newer, PostgreSQL 16 or newer. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` (add `--workspace` in Verity). Lockfiles are committed. The workspace also contains crates/workflow-core. Other products use its pinned Git revision; local development may temporarily use a sibling path override.

Set DATABASE_URL to a dedicated least-privilege product database, CUSTOMERS_URL to Customers, NM_TENANT to the single configured identity realm (default neuralmimicry), and NM_LISTEN (default 0.0.0.0:8080). Service URLs use <SERVICE>_URL; GAIL_TOKEN and CONDUCTOR_TOKEN are scoped upstream credentials. Caller bearer tokens are only forwarded to Customers, Relay, Verity and Refiner as required. TLS certificate verification is enabled and redirects are disabled. PostgreSQL uses an internal network connection; require cluster network isolation or a trusted TLS proxy for databases across trust boundaries.

`cargo run --release` starts the service. GET /healthz checks the process; GET /readyz checks its database. Business APIs require a live Customers observe/use/control grant for this service. Source operations also require Relay observe access and current source-purpose rights. The service never trusts forwarded identity headers or treats service-account tokens as human users. Each deployment is a single tenant realm; use separate databases and deployments for different identity realms.

HTTP bodies are limited to 1 MiB, upstream responses to 2 MiB, concurrent requests to 64, the database pool to eight and CPU evaluations to four. Requests have a 30-second timeout; CPU jobs retain their permits after caller cancellation. Product databases store mutable governed content; do not put their raw payloads in an immutable ledger. Logs avoid tokens and request bodies.

## Operations and acceptance

The deployment owner is SwarmHPC. Use `swarmhpc/ansible/continuum_tenant_verity_site.yml`, or `continuum_tenant_business_suite_site.yml` for all four. See [operations](docs/operations.md) and [QA](docs/qa.md). Production evidence must record source commit, image digest, rollout/readiness, functional checks and limitations. A healthy pod does not qualify a model or prove an external business effect.

