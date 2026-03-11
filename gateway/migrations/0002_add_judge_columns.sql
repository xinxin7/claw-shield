-- Add Judge audit columns to the traces table.
ALTER TABLE traces ADD COLUMN judge_verdict TEXT;
ALTER TABLE traces ADD COLUMN judge_action  TEXT;

CREATE INDEX IF NOT EXISTS idx_traces_judge_action
    ON traces (project_id, judge_action)
    WHERE judge_action IS NOT NULL;
