-- SmartGraphical persistence schema v1.
-- Stores uploaded artifacts and analysis scan runs.
-- Idempotent: every CREATE uses IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    language TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    path_on_disk TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifact_created_at ON artifact(created_at DESC);

CREATE TABLE IF NOT EXISTS scan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id INTEGER NOT NULL,
    mode TEXT NOT NULL,
    task TEXT NOT NULL,
    rules_run_json TEXT NOT NULL,
    findings_count INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    tool_version TEXT NOT NULL,
    rules_catalog_hash TEXT NOT NULL,
    findings_payload_path TEXT NOT NULL,
    graph_payload_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    FOREIGN KEY(artifact_id) REFERENCES artifact(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_artifact_id ON scan(artifact_id);
CREATE INDEX IF NOT EXISTS idx_scan_created_at ON scan(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_deleted_at ON scan(deleted_at);
