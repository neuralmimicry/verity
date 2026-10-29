//! Independent product databases, async bounded connection pools and immutable
//! identities. PostgreSQL coordinates concurrent replicas and crash recovery.
use crate::{ApiError, Result};
use deadpool_postgres::{Manager, Pool, Runtime};
use serde_json::Value;
use tokio_postgres::NoTls;
#[derive(Clone)]
pub struct Store {
    pub pool: Pool,
}
impl Store {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let config: tokio_postgres::Config = url.parse()?;
        let pool = Pool::builder(Manager::new(config, NoTls))
            .runtime(Runtime::Tokio1)
            .max_size(8)
            .wait_timeout(Some(std::time::Duration::from_secs(5)))
            .build()?;
        let mut db = pool.get().await?;
        let tx = db.transaction().await?;
        tx.batch_execute("SELECT pg_advisory_xact_lock(632017816)")
            .await?;
        tx.batch_execute(include_str!("../migrations/001_records.sql"))
            .await?;
        tx.commit().await?;
        Ok(Self { pool })
    }
    /// Insert once, or accept an identical replay. Conflicting reuse of an ID
    /// is never silently overwritten. UUIDs avoid leaking natural object keys.
    pub async fn insert(
        &self,
        tenant: &str,
        kind: &str,
        id: &str,
        owner: &str,
        payload: &Value,
    ) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute("INSERT INTO workflow_records (tenant,kind,id,owner,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING", &[&tenant,&kind,&id,&owner,payload]).await?;
        let row = client
            .query_one(
                "SELECT owner,payload FROM workflow_records WHERE tenant=$1 AND kind=$2 AND id=$3",
                &[&tenant, &kind, &id],
            )
            .await?;
        if row.get::<_, String>(0) != owner || row.get::<_, Value>(1) != *payload {
            return Err(ApiError::conflict());
        }
        Ok(())
    }
    pub async fn get(&self, tenant: &str, kind: &str, id: &str) -> Result<Value> {
        self.pool
            .get()
            .await?
            .query_opt(
                "SELECT payload FROM workflow_records WHERE tenant=$1 AND kind=$2 AND id=$3",
                &[&tenant, &kind, &id],
            )
            .await?
            .map(|r| r.get(0))
            .ok_or_else(ApiError::missing)
    }
    pub async fn list(
        &self,
        tenant: &str,
        kind: &str,
        after: i64,
        limit: i64,
    ) -> Result<Vec<Value>> {
        let rows = self.pool.get().await?.query("SELECT payload || jsonb_build_object('_sequence',sequence) FROM workflow_records WHERE tenant=$1 AND kind=$2 AND sequence>$3 ORDER BY sequence LIMIT $4", &[&tenant,&kind,&after,&limit.clamp(1,500)]).await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }
}
