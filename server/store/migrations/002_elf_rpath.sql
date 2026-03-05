-- 002_elf_rpath.sql
-- Add ELF RPATH/RUNPATH detail column to events and allowed_rpaths to allowlist.

BEGIN;

ALTER TABLE events ADD COLUMN IF NOT EXISTS elf_rpath_detail JSONB;

ALTER TABLE allowlist ADD COLUMN IF NOT EXISTS allowed_rpaths JSONB;

COMMIT;
