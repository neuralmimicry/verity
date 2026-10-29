//! Source identity and purpose-specific access. Reading a record never grants
//! permission to mirror or train. Expired grants fail closed on every retrieval.
use crate::{Identity, Result, identifier, require};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub source_id: String,
    pub object_id: String,
    pub version: String,
    pub tenant: String,
    pub readers: Vec<String>,
    pub purposes: Vec<String>,
    pub observed_at: i64,
    pub access_expires_at: i64,
    pub deleted: bool,
    pub training_permitted: bool,
}
impl SourceRef {
    pub fn validate(&self, tenant: &str, now: i64) -> Result<()> {
        require(
            identifier(&self.source_id)
                && identifier(&self.object_id)
                && identifier(&self.version)
                && self.tenant == tenant
                && self.observed_at > 0
                && self.observed_at <= now
                && self.access_expires_at > now
                && self.access_expires_at <= now + 86400
                && !self.readers.is_empty()
                && self.readers.len() <= 100
                && self.readers.iter().all(|p| identifier(p))
                && !self.purposes.is_empty()
                && self.purposes.len() <= 16
                && self.purposes.iter().all(|p| identifier(p)),
            "invalid source reference",
        )
    }
    pub fn permits(&self, actor: &Identity, purpose: &str, now: i64) -> bool {
        !self.deleted
            && self.tenant == actor.tenant
            && self.access_expires_at > now
            && self.readers.contains(&actor.principal)
            && self.purposes.iter().any(|p| p == purpose)
    }
    pub fn key(&self) -> String {
        crate::digest(&(&self.source_id, &self.object_id))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revocation_expiry_and_purpose_are_enforced() {
        let mut s = SourceRef {
            source_id: "erp".into(),
            object_id: "order-1".into(),
            version: "v1".into(),
            tenant: "t".into(),
            readers: vec!["alice".into()],
            purposes: vec!["context".into()],
            observed_at: 1,
            access_expires_at: 20,
            deleted: false,
            training_permitted: false,
        };
        let a = Identity {
            principal: "alice".into(),
            tenant: "t".into(),
            bearer: String::new(),
        };
        assert!(s.permits(&a, "context", 10));
        assert!(!s.permits(&a, "training", 10));
        assert!(!s.permits(&a, "context", 20));
        s.deleted = true;
        assert!(!s.permits(&a, "context", 10));
    }
}
