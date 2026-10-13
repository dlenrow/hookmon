-- 009_kernel_release.sql
-- Track the running kernel on each host so the server can detect kernel
-- upgrades and correlate new BPF program tags with previously allowed ones.

BEGIN;

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS kernel_release      TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS prev_kernel_release  TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS kernel_changed_at    TIMESTAMPTZ;

COMMIT;
