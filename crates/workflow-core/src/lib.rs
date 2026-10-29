//! Versioned business-workflow contracts. Shared infrastructure has one owner;
//! product semantics stay in their respective crates. No API trusts identity headers.
pub mod evidence;
pub mod runtime;
pub mod source;
pub mod store;

pub use evidence::{Evaluation, EvidenceState};
pub use runtime::{ApiError, App, Identity, Result};
pub use serde_json::{Value, json};
pub use source::SourceRef;
pub use store::Store;

/// Unix seconds are explicit throughout the wire contracts; simulated time must
/// use a separate field and cannot be passed as observation time.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}
/// serde_json's sorted object keys make this stable for the supported JSON
/// representation. This is a content identity, not a signature or truth claim.
pub fn digest(value: &impl serde::Serialize) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(
        serde_json::to_vec(value).expect("serializable contract"),
    ))
}
pub fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(ApiError::invalid(message))
    }
}
pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
}
