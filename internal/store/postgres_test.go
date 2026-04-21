package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/lease"

	"github.com/lib/pq"
)

type execRecorderDriver struct {
	exec func(query string, args []driver.NamedValue) error
}

type execRecorderConn struct {
	exec func(query string, args []driver.NamedValue) error
}

func (d *execRecorderDriver) Open(string) (driver.Conn, error) {
	return &execRecorderConn{exec: d.exec}, nil
}

func (c *execRecorderConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}
func (c *execRecorderConn) Close() error              { return nil }
func (c *execRecorderConn) Begin() (driver.Tx, error) { return nil, errors.New("not implemented") }

func (c *execRecorderConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.exec(query, args); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

var execRecorderDriverSeq uint64

func openExecRecorderDB(t *testing.T, exec func(query string, args []driver.NamedValue) error) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("approval_exec_recorder_%d", atomic.AddUint64(&execRecorderDriverSeq, 1))
	sql.Register(name, &execRecorderDriver{exec: exec})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	return db
}

func TestConsumeApprovalTicketStoresClaim(t *testing.T) {
	var gotQuery string
	var gotArgs []driver.NamedValue
	db := openExecRecorderDB(t, func(query string, args []driver.NamedValue) error {
		gotQuery = query
		gotArgs = append([]driver.NamedValue(nil), args...)
		return nil
	})
	defer db.Close()

	store := &Store{db: db}
	consumedAt := time.Unix(100, 0).UTC()
	err := store.ConsumeApprovalTicket(context.Background(), approval.UseClaim{
		TicketID:           "ticket-1",
		Nonce:              "nonce-1",
		ExecutionID:        "exec-1",
		PolicyDigest:       "policy-1",
		ActionType:         "http_request",
		ResourceDigest:     "abcd",
		ResourceDigestAlgo: "sha256",
		ConsumedAt:         consumedAt,
	})
	if err != nil {
		t.Fatalf("ConsumeApprovalTicket: %v", err)
	}
	if gotQuery == "" {
		t.Fatal("missing insert query")
	}
	if len(gotArgs) != 8 {
		t.Fatalf("arg count = %d", len(gotArgs))
	}
	if gotArgs[0].Value != "ticket-1" || gotArgs[5].Value != "abcd" || gotArgs[6].Value != "sha256" || gotArgs[7].Value != consumedAt {
		t.Fatalf("unexpected args: %+v", gotArgs)
	}
}

func TestConsumeApprovalTicketMapsDuplicateToAlreadyUsed(t *testing.T) {
	db := openExecRecorderDB(t, func(query string, args []driver.NamedValue) error {
		return &pq.Error{Code: "23505"}
	})
	defer db.Close()

	store := &Store{db: db}
	err := store.ConsumeApprovalTicket(context.Background(), approval.UseClaim{TicketID: "ticket-2"})
	if !approval.IsTicketAlreadyUsed(err) {
		t.Fatalf("expected already-used error, got %v", err)
	}
}

func TestConsumeApprovalTicketMapsExecFailureToUnavailable(t *testing.T) {
	db := openExecRecorderDB(t, func(query string, args []driver.NamedValue) error {
		return fmt.Errorf("db down")
	})
	defer db.Close()

	store := &Store{db: db}
	err := store.ConsumeApprovalTicket(context.Background(), approval.UseClaim{TicketID: "ticket-3"})
	if !approval.IsTicketUnavailable(err) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

type txRecorderState struct {
	remainingByGrant map[string]int64
	approvalRows     map[string]approval.UseClaim
	beginErr         error
	selectErr        error
	insertErr        error
	updateErr        error
	commitErr        error
}

type txRecorderDriver struct {
	state *txRecorderState
}

type txRecorderConn struct {
	state *txRecorderState
	tx    *txRecorderTxn
}

type txRecorderTxn struct {
	conn             *txRecorderConn
	remainingByGrant map[string]int64
	approvalRows     map[string]approval.UseClaim
}

type txRecorderRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (d *txRecorderDriver) Open(string) (driver.Conn, error) {
	return &txRecorderConn{state: d.state}, nil
}

func (c *txRecorderConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *txRecorderConn) Close() error { return nil }

func (c *txRecorderConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *txRecorderConn) BeginTx(_ context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if c.state.beginErr != nil {
		return nil, c.state.beginErr
	}
	c.tx = &txRecorderTxn{
		conn:             c,
		remainingByGrant: cloneRemaining(c.state.remainingByGrant),
		approvalRows:     cloneApprovalRows(c.state.approvalRows),
	}
	return c.tx, nil
}

func (c *txRecorderConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.tx == nil {
		return nil, errors.New("transaction not started")
	}
	switch {
	case strings.Contains(query, "INSERT INTO approval_ticket_uses"):
		if c.state.insertErr != nil {
			return nil, c.state.insertErr
		}
		ticketID, _ := args[0].Value.(string)
		if _, exists := c.tx.approvalRows[ticketID]; exists {
			return nil, &pq.Error{Code: "23505"}
		}
		c.tx.approvalRows[ticketID] = approval.UseClaim{TicketID: ticketID}
		return driver.RowsAffected(1), nil
	default:
		return nil, fmt.Errorf("unexpected exec query: %s", query)
	}
}

func (c *txRecorderConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.tx == nil {
		return nil, errors.New("transaction not started")
	}
	switch {
	case strings.Contains(query, "SELECT remaining_count"):
		if c.state.selectErr != nil {
			return nil, c.state.selectErr
		}
		grantID, _ := args[1].Value.(string)
		remaining, ok := c.tx.remainingByGrant[grantID]
		if !ok {
			return &txRecorderRows{columns: []string{"remaining_count"}}, nil
		}
		return &txRecorderRows{
			columns: []string{"remaining_count"},
			values:  [][]driver.Value{{remaining}},
		}, nil
	case strings.Contains(query, "UPDATE side_effect_lease_grants"):
		if c.state.updateErr != nil {
			return nil, c.state.updateErr
		}
		grantID, _ := args[1].Value.(string)
		remaining, ok := c.tx.remainingByGrant[grantID]
		if !ok {
			return &txRecorderRows{columns: []string{"remaining_count"}}, nil
		}
		remaining--
		c.tx.remainingByGrant[grantID] = remaining
		return &txRecorderRows{
			columns: []string{"remaining_count"},
			values:  [][]driver.Value{{remaining}},
		}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

func (tx *txRecorderTxn) Commit() error {
	if tx.conn == nil {
		return nil
	}
	if tx.conn.state.commitErr != nil {
		tx.conn.tx = nil
		return tx.conn.state.commitErr
	}
	tx.conn.state.remainingByGrant = cloneRemaining(tx.remainingByGrant)
	tx.conn.state.approvalRows = cloneApprovalRows(tx.approvalRows)
	tx.conn.tx = nil
	return nil
}

func (tx *txRecorderTxn) Rollback() error {
	if tx.conn != nil {
		tx.conn.tx = nil
	}
	return nil
}

func (r *txRecorderRows) Columns() []string { return append([]string(nil), r.columns...) }

func (r *txRecorderRows) Close() error { return nil }

func (r *txRecorderRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

var txRecorderDriverSeq uint64

func openTxRecorderDB(t *testing.T, state *txRecorderState) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("lease_tx_recorder_%d", atomic.AddUint64(&txRecorderDriverSeq, 1))
	sql.Register(name, &txRecorderDriver{state: state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	return db
}

func cloneRemaining(input map[string]int64) map[string]int64 {
	if input == nil {
		return map[string]int64{}
	}
	result := make(map[string]int64, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func cloneApprovalRows(input map[string]approval.UseClaim) map[string]approval.UseClaim {
	if input == nil {
		return map[string]approval.UseClaim{}
	}
	result := make(map[string]approval.UseClaim, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func testLeaseConsumeClaim(ticketID string) approval.UseClaim {
	return approval.UseClaim{
		TicketID:           ticketID,
		Nonce:              "nonce-" + ticketID,
		ExecutionID:        "exec-1",
		PolicyDigest:       "policy-1",
		ActionType:         "http_request",
		ResourceDigest:     "abcd",
		ResourceDigestAlgo: "sha256",
		ConsumedAt:         time.Unix(100, 0).UTC(),
	}
}

func TestConsumeApprovalDuplicateLeavesLeaseBudgetUnchanged(t *testing.T) {
	state := &txRecorderState{
		remainingByGrant: map[string]int64{"grant-1": 2},
		approvalRows:     map[string]approval.UseClaim{"ticket-dup": testLeaseConsumeClaim("ticket-dup")},
	}
	db := openTxRecorderDB(t, state)
	defer db.Close()

	store := &Store{db: db}
	_, err := store.Consume(context.Background(), lease.ConsumeRequest{
		LeaseID:    "lease-1",
		GrantID:    "grant-1",
		ConsumedAt: time.Unix(101, 0).UTC(),
		Approval:   ptrUseClaim(testLeaseConsumeClaim("ticket-dup")),
	})
	if !approval.IsTicketAlreadyUsed(err) {
		t.Fatalf("expected already-used error, got %v", err)
	}
	if got := state.remainingByGrant["grant-1"]; got != 2 {
		t.Fatalf("remaining count = %d, want 2", got)
	}
}

func TestConsumeLeaseBudgetExhaustedLeavesApprovalUnpersisted(t *testing.T) {
	state := &txRecorderState{
		remainingByGrant: map[string]int64{"grant-1": 0},
		approvalRows:     map[string]approval.UseClaim{},
	}
	db := openTxRecorderDB(t, state)
	defer db.Close()

	store := &Store{db: db}
	_, err := store.Consume(context.Background(), lease.ConsumeRequest{
		LeaseID:    "lease-1",
		GrantID:    "grant-1",
		ConsumedAt: time.Unix(101, 0).UTC(),
		Approval:   ptrUseClaim(testLeaseConsumeClaim("ticket-new")),
	})
	if !lease.IsBudgetExhausted(err) {
		t.Fatalf("expected budget-exhausted error, got %v", err)
	}
	if _, exists := state.approvalRows["ticket-new"]; exists {
		t.Fatal("approval row persisted despite exhausted budget")
	}
}

func TestConsumeCommitFailureLeavesNeitherApprovalNorBudgetPersisted(t *testing.T) {
	state := &txRecorderState{
		remainingByGrant: map[string]int64{"grant-1": 2},
		approvalRows:     map[string]approval.UseClaim{},
		commitErr:        fmt.Errorf("commit failed"),
	}
	db := openTxRecorderDB(t, state)
	defer db.Close()

	store := &Store{db: db}
	_, err := store.Consume(context.Background(), lease.ConsumeRequest{
		LeaseID:    "lease-1",
		GrantID:    "grant-1",
		ConsumedAt: time.Unix(101, 0).UTC(),
		Approval:   ptrUseClaim(testLeaseConsumeClaim("ticket-new")),
	})
	if !lease.IsLeaseUnavailable(err) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
	if got := state.remainingByGrant["grant-1"]; got != 2 {
		t.Fatalf("remaining count = %d, want 2", got)
	}
	if _, exists := state.approvalRows["ticket-new"]; exists {
		t.Fatal("approval row persisted despite failed commit")
	}
}

func TestConsumeSuccessPersistsApprovalAndLeaseBudgetTogether(t *testing.T) {
	state := &txRecorderState{
		remainingByGrant: map[string]int64{"grant-1": 2},
		approvalRows:     map[string]approval.UseClaim{},
	}
	db := openTxRecorderDB(t, state)
	defer db.Close()

	store := &Store{db: db}
	result, err := store.Consume(context.Background(), lease.ConsumeRequest{
		LeaseID:    "lease-1",
		GrantID:    "grant-1",
		ConsumedAt: time.Unix(101, 0).UTC(),
		Approval:   ptrUseClaim(testLeaseConsumeClaim("ticket-new")),
	})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got, want := result.RemainingCount, uint64(1); got != want {
		t.Fatalf("remaining count = %d, want %d", got, want)
	}
	if got := state.remainingByGrant["grant-1"]; got != 1 {
		t.Fatalf("persisted remaining count = %d, want 1", got)
	}
	if _, exists := state.approvalRows["ticket-new"]; !exists {
		t.Fatal("approval row was not persisted")
	}
}

func ptrUseClaim(value approval.UseClaim) *approval.UseClaim {
	return &value
}
