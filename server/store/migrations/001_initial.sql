-- 001_initial.sql
-- Initial schema for HookMon event store, allowlist, and audit log.

BEGIN;

-- events stores every hook event detected by agents.
CREATE TABLE IF NOT EXISTS events (
    id            TEXT        PRIMARY KEY,
    timestamp     TIMESTAMPTZ NOT NULL,
    host_id       TEXT        NOT NULL,
    hostname      TEXT        NOT NULL,

    event_type    TEXT        NOT NULL,
    severity      TEXT        NOT NULL,

    -- Process context
    pid           INTEGER     NOT NULL DEFAULT 0,
    ppid          INTEGER     NOT NULL DEFAULT 0,
    uid           INTEGER     NOT NULL DEFAULT 0,
    gid           INTEGER     NOT NULL DEFAULT 0,
    comm          TEXT        NOT NULL DEFAULT '',
    cmdline       TEXT        NOT NULL DEFAULT '',
    exe_path      TEXT        NOT NULL DEFAULT '',
    exe_hash      TEXT        NOT NULL DEFAULT '',
    cgroup_path   TEXT        NOT NULL DEFAULT '',
    container_id  TEXT        NOT NULL DEFAULT '',
    namespace     TEXT        NOT NULL DEFAULT '',

    -- Event-type-specific detail payloads stored as JSONB
    bpf_detail     JSONB,
    preload_detail JSONB,
    shm_detail     JSONB,
    dlopen_detail  JSONB,

    -- Policy evaluation result (filled after allowlist evaluation)
    policy_result  JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_host_timestamp ON events (host_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_event_type     ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity       ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp       ON events (timestamp DESC);

-- allowlist stores the approved (or denied) hook patterns.
CREATE TABLE IF NOT EXISTS allowlist (
    id              TEXT        PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',

    -- Match criteria
    event_types     JSONB       NOT NULL DEFAULT '[]'::JSONB,
    exe_hash        TEXT        NOT NULL DEFAULT '',
    exe_path        TEXT        NOT NULL DEFAULT '',
    library_hash    TEXT        NOT NULL DEFAULT '',
    library_path    TEXT        NOT NULL DEFAULT '',
    prog_name       TEXT        NOT NULL DEFAULT '',
    prog_type       INTEGER,
    host_pattern    TEXT        NOT NULL DEFAULT '',
    uid_range       JSONB,
    container_image TEXT        NOT NULL DEFAULT '',

    -- Policy
    action          TEXT        NOT NULL DEFAULT 'ALERT',
    expires         TIMESTAMPTZ,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON allowlist (enabled);

-- audit_log tracks administrative actions (policy changes, approvals, etc.).
CREATE TABLE IF NOT EXISTS audit_log (
    id        TEXT        PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action    TEXT        NOT NULL,
    username  TEXT        NOT NULL DEFAULT '',
    details   JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action    ON audit_log (action);

COMMIT;
