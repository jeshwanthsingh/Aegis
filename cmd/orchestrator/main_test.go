package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis/internal/receipt"
	"aegis/internal/store"
	"aegis/internal/telemetry"
)

func TestReconcileMarksInflightAndRemovesOrphans(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AEGIS_CGROUP_PARENT", filepath.Join(root, "cgroups"))

	scratch := filepath.Join(root, "scratch-exec123.ext4")
	socket := filepath.Join("/tmp/aegis", "fc-exec123.sock")
	vsock := filepath.Join("/tmp/aegis", "vsock-exec123.sock")
	if err := os.MkdirAll("/tmp/aegis", 0o700); err != nil {
		t.Fatalf("MkdirAll /tmp/aegis: %v", err)
	}
	for _, path := range []string{scratch, socket, vsock} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	cgroupPath := filepath.Join(root, "cgroups", "exec123")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("MkdirAll cgroupPath: %v", err)
	}

	origGlob := globScratchPathsFunc
	origMarkInflight := markInFlightReconciledFunc
	origMarkExec := markExecutionReconciledFunc
	origLoadExec := loadExecutionRecordFunc
	origEmitReconciledReceipt := emitReconciledReceiptFunc
	t.Cleanup(func() {
		globScratchPathsFunc = origGlob
		markInFlightReconciledFunc = origMarkInflight
		markExecutionReconciledFunc = origMarkExec
		loadExecutionRecordFunc = origLoadExec
		emitReconciledReceiptFunc = origEmitReconciledReceipt
	})

	globScratchPathsFunc = func(string) ([]string, error) {
		return []string{scratch}, nil
	}
	inflightMarked := 0
	recoveredIDs := []string{}
	markInFlightReconciledFunc = func(*store.Store) error {
		inflightMarked++
		return nil
	}
	markExecutionReconciledFunc = func(_ *store.Store, executionID string) error {
		recoveredIDs = append(recoveredIDs, executionID)
		return nil
	}
	loadExecutionRecordFunc = func(_ *store.Store, executionID string) (store.ExecutionRecord, error) {
		return store.ExecutionRecord{ExecutionID: executionID, Status: store.StatusReconciled, CreatedAt: time.Unix(1, 0)}, nil
	}
	var (
		receiptExecID  string
		receiptCleanup telemetry.CleanupDoneData
	)
	emitReconciledReceiptFunc = func(rec store.ExecutionRecord, cleanup telemetry.CleanupDoneData) (receipt.BundlePaths, error) {
		receiptExecID = rec.ExecutionID
		receiptCleanup = cleanup
		return receipt.BundlePaths{ProofDir: "/tmp/aegis/proofs/" + rec.ExecutionID}, nil
	}

	reconcile(nil)

	if inflightMarked != 1 {
		t.Fatalf("markInFlightReconciled calls = %d, want 1", inflightMarked)
	}
	if len(recoveredIDs) != 1 || recoveredIDs[0] != "exec123" {
		t.Fatalf("recoveredIDs = %v, want [exec123]", recoveredIDs)
	}
	if receiptExecID != "exec123" {
		t.Fatalf("receiptExecID = %q, want exec123", receiptExecID)
	}
	if !receiptCleanup.ScratchRemoved || !receiptCleanup.SocketRemoved || !receiptCleanup.CgroupRemoved || !receiptCleanup.AllClean {
		t.Fatalf("receiptCleanup = %+v, want scratch/socket/cgroup/all clean true", receiptCleanup)
	}
	for _, path := range []string{scratch, socket, vsock, cgroupPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", path, err)
		}
	}
}

func TestReconcileRemovesUntrackedWarmOrphansWithoutReceipt(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AEGIS_CGROUP_PARENT", filepath.Join(root, "cgroups"))

	scratch := filepath.Join(root, "scratch-warm123.ext4")
	socket := filepath.Join("/tmp/aegis", "fc-warm123.sock")
	vsock := filepath.Join("/tmp/aegis", "vsock-warm123.sock")
	if err := os.MkdirAll("/tmp/aegis", 0o700); err != nil {
		t.Fatalf("MkdirAll /tmp/aegis: %v", err)
	}
	for _, path := range []string{scratch, socket, vsock} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	cgroupPath := filepath.Join(root, "cgroups", "warm123")
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		t.Fatalf("MkdirAll cgroupPath: %v", err)
	}

	origGlob := globScratchPathsFunc
	origMarkInflight := markInFlightReconciledFunc
	origMarkExec := markExecutionReconciledFunc
	origLoadExec := loadExecutionRecordFunc
	origEmitReconciledReceipt := emitReconciledReceiptFunc
	t.Cleanup(func() {
		globScratchPathsFunc = origGlob
		markInFlightReconciledFunc = origMarkInflight
		markExecutionReconciledFunc = origMarkExec
		loadExecutionRecordFunc = origLoadExec
		emitReconciledReceiptFunc = origEmitReconciledReceipt
	})

	globScratchPathsFunc = func(string) ([]string, error) { return []string{scratch}, nil }
	markInFlightReconciledFunc = func(*store.Store) error { return nil }
	markExecutionCalls := 0
	markExecutionReconciledFunc = func(_ *store.Store, executionID string) error {
		markExecutionCalls++
		return nil
	}
	loadExecutionRecordFunc = func(_ *store.Store, executionID string) (store.ExecutionRecord, error) {
		return store.ExecutionRecord{}, sql.ErrNoRows
	}
	receiptCalls := 0
	emitReconciledReceiptFunc = func(store.ExecutionRecord, telemetry.CleanupDoneData) (receipt.BundlePaths, error) {
		receiptCalls++
		return receipt.BundlePaths{}, nil
	}

	reconcile(nil)

	if markExecutionCalls != 0 {
		t.Fatalf("markExecutionReconciled calls = %d, want 0", markExecutionCalls)
	}
	if receiptCalls != 0 {
		t.Fatalf("emitReconciledReceipt calls = %d, want 0", receiptCalls)
	}
	for _, path := range []string{scratch, socket, vsock, cgroupPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", path, err)
		}
	}
}
