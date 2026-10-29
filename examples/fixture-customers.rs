//! Offline-only upstream fixture. This example is never part of a service
//! container and must bind loopback. It cannot qualify production evidence.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[derive(Clone, Default)]
struct Fixture {
    approval: Arc<tokio::sync::RwLock<Value>>,
    calls: Arc<AtomicUsize>,
}
async fn session(headers: HeaderMap) -> Json<Value> {
    let user = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some("Bearer fixture-alice") => "alice",
        Some("Bearer fixture-bob") => "bob",
        _ => return Json(json!({"authenticated":false})),
    };
    let grants: serde_json::Map<String, Value> = ["cora", "relay", "verity", "foresight"]
        .into_iter()
        .map(|s| (s.into(), json!({"access_level":"control"})))
        .collect();
    Json(
        json!({"authenticated":true,"user":user,"identity_type":"service_account","service_access":grants}),
    )
}
async fn approval(State(s): State<Fixture>, Json(value): Json<Value>) -> Json<Value> {
    *s.approval.write().await = value;
    Json(json!({"fixture_only":true}))
}
async fn work(State(s): State<Fixture>, Path(id): Path<String>) -> Json<Value> {
    let operation = s.approval.read().await.clone();
    let status = if operation["arguments"]["closed_work"] == true {
        "success"
    } else {
        "in_operation"
    };
    Json(
        json!({"id":id,"execution_approved":true,"status":status,"plan":{"relay_operation":operation}}),
    )
}
async fn call(
    State(s): State<Fixture>,
    Path(_): Path<String>,
    Json(value): Json<Value>,
) -> (StatusCode, Json<Value>) {
    s.calls.fetch_add(1, Ordering::SeqCst);
    if value["arguments"]["fail"] == true {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"fixture_ambiguous"})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"result":{"isError":false,"content":[{"type":"text","text":"fixture-only"}]}})),
    )
}
async fn calls(State(s): State<Fixture>) -> Json<Value> {
    Json(json!({"calls":s.calls.load(Ordering::SeqCst)}))
}
async fn briefing(Json(value): Json<Value>) -> Json<Value> {
    Json(
        json!({"answer":"fixture-only current commitment","fixture_only":true,
        "permissions":{"capture":value["question"]=="unsafe-permissions","mirror":false,"train":false}}),
    )
}
#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/api/session", get(session))
        .route("/fixture/approval", post(approval))
        .route("/fixture/calls", get(calls))
        .route("/v1/business/briefings", post(briefing))
        .route("/api/v1/work-items/{id}", get(work))
        .route("/api/mcp/servers/{name}/call", post(call))
        .with_state(Fixture::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18080")
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();
}
