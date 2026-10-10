-- 004_enrollment.sql
-- Enrollment and host identity (fix plan step 7a).
--
-- hosts.sensors holds the sensor-registry snapshot from the host's latest
-- heartbeat: a JSON array of {name, status, reason}.
--
-- enrollment_token_uses records each single-use enrollment token when it is
-- used, by the SHA-256 of its secret (the secret is never stored). The
-- primary key makes a second use fail, across concurrent enrollments and
-- server restarts.

BEGIN;

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS sensors JSONB;

CREATE TABLE IF NOT EXISTS enrollment_token_uses (
    token_fingerprint TEXT        PRIMARY KEY,
    token_name        TEXT        NOT NULL,
    host_id           TEXT        NOT NULL,
    used_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
