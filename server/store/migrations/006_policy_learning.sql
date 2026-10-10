-- 006_policy_learning.sql
-- Allowlist scopes, review state and learning mode (fix plan step 7c).
--
-- allowlist gains the columns the matcher reads but the table never had:
--   prog_hash  the kernel program tag; the INSERT used to drop it.
--   host_id    an entry scoped to one enrolled host; '' is the whole fleet.
--   status     APPROVED (in force), PENDING (a learning-mode candidate,
--              never matches) or REJECTED (matches with action ALERT).
-- and the learning-mode record of a candidate:
--   learned_key       the dedupe key (event type, exe hash, subject,
--                     container context) as JSON; NULL on entries written
--                     by hand.
--   candidate_key     the key's SHA-256, so PENDING entries can be unique
--                     per key whatever the length of a path in it.
--   learned_exe_path, occurrences, first_seen, last_seen, seen_hosts
--
-- learning_mode holds the learning windows: one row for the fleet
-- (host_id '') and one per host in learning mode. A window is open until
-- ends_at.

BEGIN;

ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS prog_hash        TEXT        NOT NULL DEFAULT '';
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS host_id          TEXT        NOT NULL DEFAULT '';
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS status           TEXT        NOT NULL DEFAULT 'APPROVED';
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS candidate_key    TEXT        NOT NULL DEFAULT '';
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS learned_key      JSONB;
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS learned_exe_path TEXT        NOT NULL DEFAULT '';
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS occurrences      BIGINT      NOT NULL DEFAULT 0;
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS first_seen       TIMESTAMPTZ;
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS last_seen        TIMESTAMPTZ;
ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS seen_hosts       TEXT[]      NOT NULL DEFAULT '{}';

CREATE UNIQUE INDEX IF NOT EXISTS idx_allowlist_pending_key
    ON allowlist (candidate_key) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_allowlist_status ON allowlist (status);

CREATE TABLE IF NOT EXISTS learning_mode (
    host_id    TEXT        PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at    TIMESTAMPTZ NOT NULL,
    started_by TEXT        NOT NULL DEFAULT ''
);

COMMIT;
