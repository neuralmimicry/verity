//! Bounded Tokio HTTP runtime and live Customers authorization. Credentials are
//! forwarded only to configured service origins; redirects and automatic retries
//! are disabled. Every request rechecks grants, so revocation has no cache window.
use crate::{Store, identifier};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::Client;
use serde_json::{Value, json};
use std::{env, sync::Arc, time::Duration};
pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub &'static str);
impl ApiError {
    pub fn invalid(_: &str) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, "invalid_contract")
    }
    pub fn forbidden() -> Self {
        Self(StatusCode::FORBIDDEN, "forbidden")
    }
    pub fn unavailable() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
    }
    pub fn conflict() -> Self {
        Self(StatusCode::CONFLICT, "revision_conflict")
    }
    pub fn missing() -> Self {
        Self(StatusCode::NOT_FOUND, "not_found")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<tokio_postgres::Error> for ApiError {
    fn from(e: tokio_postgres::Error) -> Self {
        tracing::error!(code = ?e.code(), "database operation failed");
        Self::unavailable()
    }
}
impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::unavailable()
    }
}
#[derive(Clone, Debug)]
pub struct Identity {
    pub principal: String,
    pub tenant: String,
    pub bearer: String,
}
#[derive(Clone)]
pub struct App {
    pub name: &'static str,
    pub store: Store,
    pub client: Client,
    pub tenant: Arc<str>,
    customers: Arc<str>,
    pub cpu_slots: Arc<tokio::sync::Semaphore>,
}
impl App {
    pub async fn from_env(name: &'static str) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(25))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let tenant = env::var("NM_TENANT").unwrap_or_else(|_| "neuralmimicry".into());
        anyhow::ensure!(identifier(&tenant), "invalid NM_TENANT");
        Ok(Self {
            name,
            store: Store::connect(&env::var("DATABASE_URL")?).await?,
            client,
            tenant: tenant.into(),
            customers: env::var("CUSTOMERS_URL")
                .unwrap_or_else(|_| "http://customers.customers.svc.cluster.local:5010".into())
                .into(),
            cpu_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }
    pub async fn authorize(&self, headers: &HeaderMap, level: &str) -> Result<Identity> {
        let bearer = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .filter(|v| v.starts_with("Bearer ") && v.len() > 7)
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let session = self
            .remote(
                reqwest::Method::GET,
                &format!("{}/api/session", self.customers.trim_end_matches('/')),
                bearer,
                None,
            )
            .await?;
        require_access(&session, self.name, level)?;
        let principal = session["user"]
            .as_str()
            .filter(|v| identifier(v))
            .ok_or_else(ApiError::forbidden)?;
        Ok(Identity {
            principal: principal.into(),
            tenant: self.tenant.to_string(),
            bearer: bearer.into(),
        })
    }
    /// Upstream bodies are read incrementally with a hard bound, including when
    /// Content-Length is missing or false. Raw remote errors never reach clients.
    pub async fn remote(
        &self,
        method: reqwest::Method,
        url: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        use futures_util::StreamExt;
        let mut request = self.client.request(method, url);
        if !bearer.is_empty() {
            request = request.header("authorization", bearer);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| ApiError::unavailable())?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(ApiError(response.status(), "upstream_access_denied"));
        }
        if !response.status().is_success() {
            return Err(ApiError::unavailable());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ApiError::unavailable())?;
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(ApiError::unavailable());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| ApiError::unavailable())
    }
    pub async fn get(&self, url: &str, bearer: &str) -> Result<Value> {
        self.remote(reqwest::Method::GET, url, bearer, None).await
    }
    pub async fn post(&self, url: &str, bearer: &str, body: &Value) -> Result<Value> {
        self.remote(reqwest::Method::POST, url, bearer, Some(body))
            .await
    }
    /// Source grants come from Relay, never from a use-level caller's payload.
    /// The exact version and purpose are checked by every consuming service.
    pub async fn source(
        &self,
        actor: &Identity,
        source: &crate::SourceRef,
        purpose: &str,
    ) -> Result<crate::SourceRef> {
        if !crate::identifier(&source.source_id)
            || !crate::identifier(&source.object_id)
            || !crate::identifier(purpose)
        {
            return Err(ApiError::invalid("source identity"));
        }
        let relay = Self::upstream("relay", "http://relay.relay.svc.cluster.local:8080");
        let value = self
            .get(
                &format!(
                    "{relay}/v1/sources/{}/{}?purpose={purpose}",
                    source.source_id, source.object_id
                ),
                &actor.bearer,
            )
            .await?;
        let current: crate::SourceRef =
            serde_json::from_value(value).map_err(|_| ApiError::unavailable())?;
        if !current.permits(actor, purpose, crate::now()) {
            return Err(ApiError::forbidden());
        }
        Ok(current)
    }
    pub fn upstream_token(name: &str) -> String {
        env::var(format!("{}_TOKEN", name.to_ascii_uppercase()))
            .map(|v| format!("Bearer {v}"))
            .unwrap_or_default()
    }
    pub fn upstream(name: &str, default: &str) -> String {
        env::var(format!("{}_URL", name.to_ascii_uppercase()))
            .unwrap_or_else(|_| default.into())
            .trim_end_matches('/')
            .into()
    }
}
pub fn require_access(session: &Value, service: &str, level: &str) -> Result<()> {
    if session["authenticated"] != true {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let current = session["service_access"][service]["access_level"]
        .as_str()
        .unwrap_or("none");
    let rank = |s| match s {
        "observe" => 1,
        "use" => 2,
        "control" => 3,
        _ => 0,
    };
    if rank(current) < rank(level) || rank(level) == 0 {
        return Err(ApiError::forbidden());
    }
    Ok(())
}
async fn health(State(app): State<App>) -> Json<Value> {
    Json(json!({"service":app.name,"version":env!("CARGO_PKG_VERSION"),"status":"alive"}))
}
async fn ready(State(app): State<App>) -> Result<Json<Value>> {
    app.store.pool.get().await?.simple_query("SELECT 1").await?;
    Ok(Json(json!({"status":"ready","service":app.name})))
}
/// Erase mutable derived content only after Relay attests a current tombstone.
/// Minimal receipt identities remain to prevent a deleted action being repeated.
async fn purge(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<crate::SourceRef>,
) -> Result<Json<Value>> {
    let actor = app.authorize(&headers, "control").await?;
    if !identifier(&input.source_id) || !identifier(&input.object_id) {
        return Err(ApiError::invalid("source"));
    }
    let relay = App::upstream("relay", "http://relay.relay.svc.cluster.local:8080");
    let value = app
        .get(
            &format!(
                "{relay}/v1/sources/{}/{}?purpose=deletion",
                input.source_id, input.object_id
            ),
            &actor.bearer,
        )
        .await?;
    let current: crate::SourceRef =
        serde_json::from_value(value).map_err(|_| ApiError::unavailable())?;
    if !current.deleted
        || current.tenant != actor.tenant
        || !current.readers.contains(&actor.principal)
    {
        return Err(ApiError::forbidden());
    }
    let mut db = app.store.pool.get().await?;
    let tx = db.transaction().await?;
    let removed=tx.execute(
        "DELETE FROM workflow_records WHERE tenant=$1 AND kind IN ('context','evaluation','prediction','outcome')
          AND COALESCE(payload->'source',payload->'record'->'source',payload->'outcome'->'source')->>'source_id'=$2
          AND COALESCE(payload->'source',payload->'record'->'source',payload->'outcome'->'source')->>'object_id'=$3",
        &[&actor.tenant,&input.source_id,&input.object_id]).await?;
    tx.execute(
        "UPDATE workflow_records SET payload=jsonb_set(payload,'{change,data}','null'::jsonb)
        WHERE tenant=$1 AND kind='change' AND payload->'change'->'source'->>'source_id'=$2
        AND payload->'change'->'source'->>'object_id'=$3",
        &[&actor.tenant, &input.source_id, &input.object_id],
    )
    .await?;
    tx.execute(
        "UPDATE workflow_records SET payload=jsonb_build_object(
        'actor',payload->'actor','operation_digest',payload->'operation_digest',
        'state',payload->'state','purged',true,'source', $4::jsonb)
        WHERE tenant=$1 AND kind='receipt' AND payload->'operation'->'source'->>'source_id'=$2
        AND payload->'operation'->'source'->>'object_id'=$3",
        &[
            &actor.tenant,
            &input.source_id,
            &input.object_id,
            &json!(current),
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"state":"purged","records_removed":removed,"receipt_identities_retained":true,
        "external_retention_owners":["source_system","refiner","postgres_backups"]}),
    ))
}
/// The router has bounded concurrency, payload sizes and request duration.
/// Backpressure bounds tasks; CPU workers retain their own permits on timeout.
pub async fn serve(app: App, routes: Router<App>) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init()
        .ok();
    let router = routes
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/retention/purge", post(purge))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(tower::limit::ConcurrencyLimitLayer::new(64))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(
        env::var("NM_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()),
    )
    .await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM");
                tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        })
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_are_explicit_and_revocable() {
        let s = json!({"authenticated":true,"service_access":{"cora":{"access_level":"use"}}});
        assert!(require_access(&s, "cora", "use").is_ok());
        assert!(require_access(&s, "cora", "control").is_err());
        assert!(require_access(&s, "relay", "observe").is_err());
        assert!(require_access(&json!({"authenticated":false}), "cora", "observe").is_err());
    }
}
