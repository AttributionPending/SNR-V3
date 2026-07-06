-- Analyst Workbench: distinguish AI-analyzed sessions from analyst-authored
-- ("workbench") original-research reports. 'analysis' preserves existing rows.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'analysis';
