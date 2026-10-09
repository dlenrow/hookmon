-- 003_bpf_inventory.sql
-- Add the BPF_INVENTORY detail column to events. The new BPFDetail fields
-- (prog_id, load_time, created_by_uid, attach_target) live in the existing
-- bpf_detail JSONB column and need no schema change.

BEGIN;

ALTER TABLE events ADD COLUMN IF NOT EXISTS bpf_inventory_detail JSONB;

COMMIT;
