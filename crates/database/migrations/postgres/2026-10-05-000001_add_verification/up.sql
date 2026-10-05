-- When a target confirmed the file is present (e.g. visible in a Plex library),
-- and why the most recent attempt did not succeed.
ALTER TABLE scan_events ADD COLUMN verified_at TIMESTAMP;
ALTER TABLE scan_events ADD COLUMN last_error TEXT;
