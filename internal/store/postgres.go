package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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
	Outcome     string
	Status      string
	StdoutBytes int
	StderrBytes int
	ErrorMsg    string
	CreatedAt   time.Time
}

const (
	StatusRequested      = "requested"
	StatusBooting        = "booting"
	StatusGuestReady     = "guest_ready"
	StatusRunning        = "running"
	StatusFinalizing     = "finalizing"
	StatusCompleted      = "completed"
	StatusTimedOut       = "timed_out"
	StatusSandboxError   = "sandbox_error"
	StatusTeardownFailed = "teardown_failed"
	StatusReconciled     = "reconciled"
)

func statusRank(status string) int {
	switch status {
	case StatusRequested:
		return 10
	case StatusBooting:
		return 20
	case StatusGuestReady:
		return 30
	case StatusRunning:
		return 40
	case StatusFinalizing:
		return 50
	case StatusCompleted:
		return 60
	case StatusTimedOut:
		return 70
	case StatusSandboxError:
		return 80
	case StatusTeardownFailed:
		return 90
	case StatusReconciled:
		return 100
	default:
		return 0
	}
}

func isTerminalStatus(status string) bool {
	switch status {
	case StatusCompleted, StatusTimedOut, StatusSandboxError, StatusTeardownFailed, StatusReconciled:
		return true
	default:
		return false
	}
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
		status = StatusCompleted
	}
	outcome := r.Outcome
	if outcome == "" {
		if isTerminalStatus(status) {
			outcome = "error"
		} else {
			outcome = "pending"
		}
	}
	currentStatus, err := s.currentStatus(r.ExecutionID)
	if err != nil {
		return err
	}
	if statusRank(status) < statusRank(currentStatus) {
		return nil
	}
	if currentStatus == "" {
		var (
			exitCodeArg any
			durationArg any
			stdoutBytes any
			stderrBytes any
			errorMsgArg any
		)
		if isTerminalStatus(status) {
			exitCodeArg = r.ExitCode
			durationArg = r.DurationMs
			stdoutBytes = r.StdoutBytes
			stderrBytes = r.StderrBytes
		}
		if r.ErrorMsg != "" {
			errorMsgArg = r.ErrorMsg
		}
		_, err := s.db.Exec(`
			INSERT INTO executions
				(execution_id, lang, exit_code, duration_ms, outcome, status, stdout_bytes, stderr_bytes, error_msg)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			r.ExecutionID, r.Lang, exitCodeArg, durationArg, outcome, status, stdoutBytes, stderrBytes, errorMsgArg,
		)
		return err
	}

	if !isTerminalStatus(status) {
		_, err := s.db.Exec(`
			UPDATE executions
			SET lang = $2, outcome = $3, status = $4,
				error_msg = CASE WHEN $5 <> '' THEN $5 ELSE error_msg END
			WHERE execution_id = $1`,
			r.ExecutionID, r.Lang, outcome, status, r.ErrorMsg,
		)
		return err
	}

	_, err = s.db.Exec(`
		UPDATE executions
		SET lang = $2, exit_code = $3, duration_ms = $4, outcome = $5, status = $6,
			stdout_bytes = $7, stderr_bytes = $8,
			error_msg = CASE WHEN $9 <> '' THEN $9 ELSE error_msg END
		WHERE execution_id = $1`,
		r.ExecutionID, r.Lang, r.ExitCode, r.DurationMs, outcome, status, r.StdoutBytes, r.StderrBytes, r.ErrorMsg,
	)
	return err
}

func (s *Store) currentStatus(executionID string) (string, error) {
	var status string
	err := s.db.QueryRow(`SELECT status FROM executions WHERE execution_id = $1`, executionID).Scan(&status)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return status, nil
}

func (s *Store) GetExecution(executionID string) (ExecutionRecord, error) {
	var rec ExecutionRecord
	var (
		exitCode    sql.NullInt64
		durationMs  sql.NullInt64
		stdoutBytes sql.NullInt64
		stderrBytes sql.NullInt64
		errorMsg    sql.NullString
	)
	err := s.db.QueryRow(`
		SELECT execution_id, lang, exit_code, duration_ms, outcome, status,
		       stdout_bytes, stderr_bytes, error_msg, created_at
		FROM executions
		WHERE execution_id = $1`,
		executionID,
	).Scan(
		&rec.ExecutionID,
		&rec.Lang,
		&exitCode,
		&durationMs,
		&rec.Outcome,
		&rec.Status,
		&stdoutBytes,
		&stderrBytes,
		&errorMsg,
		&rec.CreatedAt,
	)
	if err != nil {
		return ExecutionRecord{}, err
	}
	if exitCode.Valid {
		rec.ExitCode = int(exitCode.Int64)
	}
	if durationMs.Valid {
		rec.DurationMs = durationMs.Int64
	}
	if stdoutBytes.Valid {
		rec.StdoutBytes = int(stdoutBytes.Int64)
	}
	if stderrBytes.Valid {
		rec.StderrBytes = int(stderrBytes.Int64)
	}
	if errorMsg.Valid {
		rec.ErrorMsg = errorMsg.String
	}
	return rec, nil
}

// MarkReconciled updates rows that were mid-flight during a crash.
func (s *Store) MarkReconciled(executionID string) error {
	_, err := s.db.Exec(`
		UPDATE executions SET status = 'reconciled', outcome = 'error',
		error_msg = 'recovered_on_boot'
		WHERE execution_id = $1 AND status IN ('requested', 'booting', 'guest_ready', 'running', 'finalizing')`,
		executionID,
	)
	return err
}

func (s *Store) MarkInFlightReconciled() error {
	_, err := s.db.Exec(`
		UPDATE executions SET status = 'reconciled', outcome = 'error',
		error_msg = 'recovered_on_boot'
		WHERE status IN ('requested', 'booting', 'guest_ready', 'running', 'finalizing')`)
	return err
}
