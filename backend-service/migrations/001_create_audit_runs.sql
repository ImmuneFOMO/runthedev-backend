CREATE TABLE IF NOT EXISTS audit_runs (
    id SERIAL PRIMARY KEY,
    item_type VARCHAR(10) NOT NULL CHECK (item_type IN ('server', 'skill')),
    item_dedup_key VARCHAR(500) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    result JSONB,
    score DOUBLE PRECISION,
    grade VARCHAR(5),
    requested_by VARCHAR(100) NOT NULL DEFAULT 'cron',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audit_runs_item ON audit_runs (item_type, item_dedup_key);
CREATE INDEX IF NOT EXISTS idx_audit_runs_status ON audit_runs (status);
CREATE INDEX IF NOT EXISTS idx_audit_runs_created ON audit_runs (created_at);

-- Composite index for LATERAL JOIN queries that filter on status='completed' and order by completed_at
CREATE INDEX IF NOT EXISTS idx_audit_runs_completed_lookup
    ON audit_runs (item_type, item_dedup_key, status, completed_at DESC);
