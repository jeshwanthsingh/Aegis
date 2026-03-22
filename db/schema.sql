CREATE TABLE IF NOT EXISTS executions (
  execution_id  TEXT PRIMARY KEY,
  lang          TEXT NOT NULL,
  exit_code     INTEGER,
  duration_ms   BIGINT,
  outcome       TEXT NOT NULL,
  stdout_bytes  INTEGER,
  stderr_bytes  INTEGER,
  error_msg     TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE executions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'completed';
