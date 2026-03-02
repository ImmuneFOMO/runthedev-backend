WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY item_type, item_dedup_key
            ORDER BY created_at DESC, id DESC
        ) AS rn
    FROM audit_runs
    WHERE status IN ('pending', 'running')
)
DELETE FROM audit_runs a
USING ranked r
WHERE a.id = r.id
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_runs_inflight
    ON audit_runs (item_type, item_dedup_key)
    WHERE status IN ('pending', 'running');

UPDATE audit_runs
SET completed_at = created_at
WHERE status = 'completed'
  AND completed_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE c.conname = 'chk_audit_runs_completed_at'
          AND t.relname = 'audit_runs'
          AND n.nspname = current_schema()
    ) THEN
        ALTER TABLE audit_runs
            ADD CONSTRAINT chk_audit_runs_completed_at
            CHECK (
                (status = 'completed' AND completed_at IS NOT NULL)
                OR status <> 'completed'
            );
    END IF;
END $$;
