-- Create the traces table for telemetry storage.
CREATE TABLE IF NOT EXISTS traces (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    session_id          TEXT NOT NULL DEFAULT '',
    provider            TEXT NOT NULL DEFAULT 'unknown',
    model               TEXT NOT NULL DEFAULT '',
    path                TEXT NOT NULL DEFAULT '',
    timestamp_ms        INTEGER NOT NULL,
    gateway_ms          INTEGER NOT NULL DEFAULT 0,
    upstream_ms         INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'ok',
    error_msg           TEXT,
    cot_steps           TEXT NOT NULL DEFAULT '[]',
    tool_calls          TEXT NOT NULL DEFAULT '[]',
    tool_results        TEXT NOT NULL DEFAULT '[]',
    sensitive_tool_count INTEGER NOT NULL DEFAULT 0,
    judge_verdict       TEXT,
    judge_action        TEXT
);

CREATE INDEX IF NOT EXISTS idx_traces_project_ts
    ON traces (project_id, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_traces_judge_action
    ON traces (project_id, judge_action)
    WHERE judge_action IS NOT NULL;
