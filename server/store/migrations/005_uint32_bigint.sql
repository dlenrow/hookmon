-- 005_uint32_bigint.sql
-- Store uint32 values in BIGINT (fix plan step 7f, pulled forward into 7b).
--
-- events.pid, ppid, uid and gid, and allowlist.prog_type, hold uint32 values
-- but were INTEGER, a signed 32-bit type. Since step 4 the bus sends UID
-- 4294967295 when a file writer's UID is unknown, and PostgreSQL rejected
-- the insert, so the event was lost.
--
-- Migrations run on every start. Only columns that are still INTEGER are
-- altered, one ALTER TABLE per table, so a table is rewritten at most once
-- and never again after that.

BEGIN;

DO $$
DECLARE
    tbl     text;
    clauses text;
BEGIN
    FOR tbl, clauses IN
        SELECT c.table_name,
               string_agg(format('ALTER COLUMN %I TYPE BIGINT', c.column_name), ', ')
        FROM information_schema.columns c
        WHERE c.table_schema = current_schema()
          AND c.data_type = 'integer'
          AND ((c.table_name = 'events' AND c.column_name IN ('pid', 'ppid', 'uid', 'gid'))
            OR (c.table_name = 'allowlist' AND c.column_name = 'prog_type'))
        GROUP BY c.table_name
    LOOP
        EXECUTE format('ALTER TABLE %I %s', tbl, clauses);
    END LOOP;
END
$$;

COMMIT;
