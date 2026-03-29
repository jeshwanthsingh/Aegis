package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Store struct {
	db *sql.DB
}

type ExecutionRecord struct {
	ExecutionID string
	Lang        string
	ExitCode    int
	DurationMs  int64
	Outcome     string // "success", "timeout", "error"
	Status      string // "booting", "running", "completed", "timed_out", "oom_killed", "sandbox_error", "teardown_failed"
	StdoutBytes int
	StderrBytes int
	ErrorMsg    string
}

func Connect(connStr string) (*Store, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) PingContext(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) WriteExecution(r ExecutionRecord) error {
	status := r.Status
	if status == "" {
		status = "completed"
	}
	_, err := s.db.Exec(`
		INSERT INTO executions
			(execution_id, lang, exit_code, duration_ms, outcome, status, stdout_bytes, stderr_bytes, error_msg)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		r.ExecutionID, r.Lang, r.ExitCode, r.DurationMs,
		r.Outcome, status, r.StdoutBytes, r.StderrBytes, r.ErrorMsg,
	)
	return err
}

// MarkSandboxError updates rows that were mid-flight during a crash.
func (s *Store) MarkSandboxError(executionID string) error {
	_, err := s.db.Exec(`
		UPDATE executions SET status = 'sandbox_error', outcome = 'error',
		error_msg = 'recovered_on_boot'
		WHERE execution_id = $1 AND status IN ('booting', 'running')`,
		executionID,
	)
	return err
}
