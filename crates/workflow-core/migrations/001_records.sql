-- Each service has its own database and least-privilege role. IDs are scoped
-- by tenant and record kind; the sequence is only an ingestion cursor.
CREATE TABLE IF NOT EXISTS workflow_records (
    sequence BIGSERIAL UNIQUE NOT NULL,
    tenant TEXT NOT NULL,
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    owner TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant,kind,id)
);
CREATE INDEX IF NOT EXISTS workflow_records_cursor ON workflow_records(tenant,kind,sequence);

