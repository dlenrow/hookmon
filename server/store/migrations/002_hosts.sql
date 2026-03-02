-- 002_hosts.sql
-- Host inventory table for enrolled agents.

BEGIN;

CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT        PRIMARY KEY,
    hostname        TEXT        NOT NULL,
    ip_address      TEXT        NOT NULL DEFAULT '',
    agent_version   TEXT        NOT NULL DEFAULT '',
    os_info         TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'ONLINE',
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hosts_status         ON hosts (status);
CREATE INDEX IF NOT EXISTS idx_hosts_last_heartbeat ON hosts (last_heartbeat);

COMMIT;
