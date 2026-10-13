-- 008_rekey_allowlist.sql
-- Re-key the allowlist on WHAT was loaded, not WHO loaded it.
--
-- LearnedKey lost event_type, exe_hash and in_container; SubjectKind values
-- changed (ld_preload, dlopen, lib_replace, etc.); ContentHash was added.
-- BPF load, attach and inventory now share one key.
--
-- PENDING entries are deleted: they will be recreated on the next occurrence
-- under the new key format.  Decided entries (APPROVED/REJECTED) lose their
-- learned key and candidate key but keep their criteria fields, so they
-- still match by criteria.  Operators re-approve them as new first sightings
-- come in under the new key.

BEGIN;

DELETE FROM allowlist WHERE status = 'PENDING';

UPDATE allowlist
SET learned_key  = NULL,
    candidate_key = ''
WHERE learned_key IS NOT NULL;

COMMIT;
