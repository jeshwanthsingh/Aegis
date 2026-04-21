package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"aegis/internal/approval"
	"aegis/internal/lease"
	"aegis/internal/dsse"
	"github.com/lib/pq"
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

func (s *Store) ConsumeApprovalTicket(ctx context.Context, claim approval.UseClaim) error {
	if s == nil || s.db == nil {
		return approval.ErrTicketUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if claim.ConsumedAt.IsZero() {
		claim.ConsumedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO approval_ticket_uses
			(ticket_id, nonce, execution_id, policy_digest, action_type, resource_digest, resource_digest_algo, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		claim.TicketID,
		claim.Nonce,
		claim.ExecutionID,
		claim.PolicyDigest,
		claim.ActionType,
		claim.ResourceDigest,
		claim.ResourceDigestAlgo,
		claim.ConsumedAt.UTC(),
	)
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if ok := AsPQError(err, &pqErr); ok && pqErr.Code == "23505" {
		return fmt.Errorf("%w: %s", approval.ErrTicketAlreadyUsed, claim.TicketID)
	}
	return fmt.Errorf("%w: %v", approval.ErrTicketUnavailable, err)
}

func (s *Store) PutIssued(ctx context.Context, record lease.IssuedRecord) error {
	if s == nil || s.db == nil {
		return lease.ErrLeaseUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if record.IssuedAt.IsZero() {
		record.IssuedAt = time.Now().UTC()
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.IssuedAt
	}
	envelopeJSON, err := json.Marshal(record.Signed.Envelope)
	if err != nil {
		return fmt.Errorf("%w: marshal lease envelope: %v", lease.ErrLeaseUnavailable, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin lease tx: %v", lease.ErrLeaseUnavailable, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO side_effect_leases
			(lease_id, execution_id, issuer, issuer_key_id, issued_at, expires_at, workload_kind, workload_boot_digest, workload_rootfs_image, policy_digest, authority_digest, envelope_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		record.LeaseID,
		record.ExecutionID,
		record.Issuer,
		record.IssuerKeyID,
		record.IssuedAt.UTC(),
		record.ExpiresAt.UTC(),
		record.Lease.Workload.Kind,
		record.Lease.Workload.BootDigest,
		record.Lease.Workload.RootfsImage,
		record.PolicyDigest,
		record.AuthorityDigest,
		envelopeJSON,
	); err != nil {
		return fmt.Errorf("%w: insert lease: %v", lease.ErrLeaseUnavailable, err)
	}
	for _, grant := range record.Lease.Grants {
		selectorDigest, selectorDigestAlgo, err := lease.DigestSelector(grant.Selector)
		if err != nil {
			return fmt.Errorf("%w: digest lease selector: %v", lease.ErrLeaseUnavailable, err)
		}
		selectorJSON, err := json.Marshal(grant.Selector)
		if err != nil {
			return fmt.Errorf("%w: marshal lease selector: %v", lease.ErrLeaseUnavailable, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO side_effect_lease_grants
				(lease_id, grant_id, action_kind, selector_kind, selector_digest, selector_digest_algo, selector_json, budget_kind, limit_count, remaining_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
			record.LeaseID,
			grant.GrantID,
			grant.ActionKind,
			grant.Selector.Kind,
			selectorDigest,
			selectorDigestAlgo,
			selectorJSON,
			grant.Budget.Kind,
			int64(grant.Budget.LimitCount),
		); err != nil {
			return fmt.Errorf("%w: insert lease grant: %v", lease.ErrLeaseUnavailable, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit lease tx: %v", lease.ErrLeaseUnavailable, err)
	}
	return nil
}

func (s *Store) LookupActiveByExecution(ctx context.Context, executionID string) (lease.IssuedRecord, error) {
	if s == nil || s.db == nil {
		return lease.IssuedRecord{}, lease.ErrLeaseUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		record       lease.IssuedRecord
		envelopeJSON []byte
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT lease_id, execution_id, issuer, issuer_key_id, issued_at, expires_at, policy_digest, authority_digest, envelope_json
		FROM side_effect_leases
		WHERE execution_id = $1`,
		executionID,
	).Scan(
		&record.LeaseID,
		&record.ExecutionID,
		&record.Issuer,
		&record.IssuerKeyID,
		&record.IssuedAt,
		&record.ExpiresAt,
		&record.PolicyDigest,
		&record.AuthorityDigest,
		&envelopeJSON,
	)
	if err == sql.ErrNoRows {
		return lease.IssuedRecord{}, lease.WrapLeaseMissing(executionID)
	}
	if err != nil {
		return lease.IssuedRecord{}, fmt.Errorf("%w: lookup lease: %v", lease.ErrLeaseUnavailable, err)
	}
	var envelope dsse.Envelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		return lease.IssuedRecord{}, fmt.Errorf("%w: decode lease envelope: %v", lease.ErrLeaseUnavailable, err)
	}
	record.Signed.Envelope = envelope
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return lease.IssuedRecord{}, fmt.Errorf("%w: decode lease payload: %v", lease.ErrLeaseUnavailable, err)
	}
	var statement lease.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return lease.IssuedRecord{}, fmt.Errorf("%w: decode lease statement: %v", lease.ErrLeaseUnavailable, err)
	}
	record.Signed.Statement = statement
	record.Lease = statement.Predicate
	return record, nil
}

func (s *Store) Consume(ctx context.Context, req lease.ConsumeRequest) (lease.ConsumeResult, error) {
	if s == nil || s.db == nil {
		return lease.ConsumeResult{}, lease.ErrLeaseUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if req.ConsumedAt.IsZero() {
		req.ConsumedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return lease.ConsumeResult{}, fmt.Errorf("%w: begin consume tx: %v", lease.ErrLeaseUnavailable, err)
	}
	defer tx.Rollback()

	var remaining int64
	err = tx.QueryRowContext(ctx, `
		SELECT remaining_count
		FROM side_effect_lease_grants
		WHERE lease_id = $1 AND grant_id = $2
		FOR UPDATE`,
		req.LeaseID,
		req.GrantID,
	).Scan(&remaining)
	if err == sql.ErrNoRows {
		return lease.ConsumeResult{}, lease.WrapLeaseMissing(req.LeaseID)
	}
	if err != nil {
		return lease.ConsumeResult{}, fmt.Errorf("%w: lock lease grant: %v", lease.ErrLeaseUnavailable, err)
	}
	if remaining <= 0 {
		return lease.ConsumeResult{}, lease.ErrBudgetExhausted
	}

	if req.Approval != nil {
		claim := *req.Approval
		if claim.ConsumedAt.IsZero() {
			claim.ConsumedAt = req.ConsumedAt.UTC()
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO approval_ticket_uses
				(ticket_id, nonce, execution_id, policy_digest, action_type, resource_digest, resource_digest_algo, consumed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			claim.TicketID,
			claim.Nonce,
			claim.ExecutionID,
			claim.PolicyDigest,
			claim.ActionType,
			claim.ResourceDigest,
			claim.ResourceDigestAlgo,
			claim.ConsumedAt.UTC(),
		); err != nil {
			var pqErr *pq.Error
			if ok := AsPQError(err, &pqErr); ok && pqErr.Code == "23505" {
				return lease.ConsumeResult{}, fmt.Errorf("%w: %s", approval.ErrTicketAlreadyUsed, claim.TicketID)
			}
			return lease.ConsumeResult{}, fmt.Errorf("%w: insert approval use: %v", lease.ErrLeaseUnavailable, err)
		}
	}

	var updatedRemaining int64
	err = tx.QueryRowContext(ctx, `
		UPDATE side_effect_lease_grants
		SET remaining_count = remaining_count - 1
		WHERE lease_id = $1 AND grant_id = $2
		RETURNING remaining_count`,
		req.LeaseID,
		req.GrantID,
	).Scan(&updatedRemaining)
	if err != nil {
		return lease.ConsumeResult{}, fmt.Errorf("%w: decrement lease budget: %v", lease.ErrLeaseUnavailable, err)
	}
	if err := tx.Commit(); err != nil {
		return lease.ConsumeResult{}, fmt.Errorf("%w: commit consume tx: %v", lease.ErrLeaseUnavailable, err)
	}
	return lease.ConsumeResult{RemainingCount: uint64(updatedRemaining)}, nil
}

func AsPQError(err error, target **pq.Error) bool {
	return err != nil && target != nil && errors.As(err, target)
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
