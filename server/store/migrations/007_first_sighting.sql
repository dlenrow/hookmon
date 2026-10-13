-- 007_first_sighting.sql
-- New hooks are recorded always, not only in learning mode: the first
-- unmatched event of a key creates its PENDING entry and is stored as the
-- first sighting; later ones only add to the entry's count. first_event_id
-- is that stored event, the evidence an operator looks at before deciding.

BEGIN;

ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS first_event_id TEXT NOT NULL DEFAULT '';

COMMIT;
