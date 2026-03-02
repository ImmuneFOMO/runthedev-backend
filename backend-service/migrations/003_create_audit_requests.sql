CREATE TABLE IF NOT EXISTS audit_requests (
    id SERIAL PRIMARY KEY,
    item_type VARCHAR(10) NOT NULL CHECK (item_type IN ('server', 'skill')),
    item_dedup_key VARCHAR(500) NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'cli',
    cli_version VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_requests_item
    ON audit_requests (item_type, item_dedup_key);
