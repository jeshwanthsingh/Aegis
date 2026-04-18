package executor

import (
	"os"
	"testing"
)

func TestVMInstanceClaimExecutionIdentityRenamesExecutionScopedResources(t *testing.T) {
	t.Parallel()

	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		t.Fatalf("MkdirAll scratchDir: %v", err)
	}

	assetID := "warm-asset-123"
	execID := "exec-claim-456"
	scratch := scratchDiskPath(assetID)
	socket := firecrackerSocketPath(assetID)
	vsock := vsockSocketPath(assetID)
	serial := serialLogFilePath(assetID)
	for _, path := range []string{scratch, socket, vsock, serial} {
		path := path
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		t.Cleanup(func() {
			_ = os.Remove(path)
		})
	}

	vm := &VMInstance{
		AssetID:       assetID,
		UUID:          assetID,
		CgroupID:      assetID,
		ScratchPath:   scratch,
		SocketPath:    socket,
		VsockPath:     vsock,
		SerialLogPath: serial,
	}

	if err := vm.ClaimExecutionIdentity(execID); err != nil {
		t.Fatalf("ClaimExecutionIdentity returned error: %v", err)
	}

	if vm.AssetID != assetID {
		t.Fatalf("AssetID = %q, want %q", vm.AssetID, assetID)
	}
	if vm.UUID != execID {
		t.Fatalf("UUID = %q, want %q", vm.UUID, execID)
	}
	if vm.CgroupID != execID {
		t.Fatalf("CgroupID = %q, want %q", vm.CgroupID, execID)
	}

	wantScratch := scratchDiskPath(execID)
	wantSocket := firecrackerSocketPath(execID)
	wantVsock := vsockSocketPath(execID)
	wantSerial := serialLogFilePath(execID)
	if vm.ScratchPath != wantScratch || vm.SocketPath != wantSocket || vm.VsockPath != wantVsock || vm.SerialLogPath != wantSerial {
		t.Fatalf("unexpected rebound paths: scratch=%q socket=%q vsock=%q serial=%q", vm.ScratchPath, vm.SocketPath, vm.VsockPath, vm.SerialLogPath)
	}

	for _, oldPath := range []string{scratch, socket, vsock, serial} {
		if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
			t.Fatalf("expected old path %s to be gone, stat err=%v", oldPath, err)
		}
	}
	for _, newPath := range []string{wantScratch, wantSocket, wantVsock, wantSerial} {
		newPath := newPath
		if _, err := os.Stat(newPath); err != nil {
			t.Fatalf("expected rebound path %s to exist: %v", newPath, err)
		}
		t.Cleanup(func() {
			_ = os.Remove(newPath)
		})
	}
}

func TestVMInstanceClaimExecutionIdentityPreservesPersistentWorkspacePath(t *testing.T) {
	t.Parallel()

	execID := "exec-claim-persistent"
	workspacePath := "/tmp/aegis/workspaces/demo.ext4"
	vm := &VMInstance{
		AssetID:       "warm-asset-persistent",
		UUID:          "warm-asset-persistent",
		CgroupID:      "warm-asset-persistent",
		ScratchPath:   workspacePath,
		SocketPath:    firecrackerSocketPath("warm-asset-persistent"),
		VsockPath:     vsockSocketPath("warm-asset-persistent"),
		SerialLogPath: serialLogFilePath("warm-asset-persistent"),
		IsPersistent:  true,
	}

	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		t.Fatalf("MkdirAll scratchDir: %v", err)
	}
	for _, path := range []string{vm.SocketPath, vm.VsockPath, vm.SerialLogPath} {
		path := path
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		t.Cleanup(func() {
			_ = os.Remove(path)
		})
	}

	if err := vm.ClaimExecutionIdentity(execID); err != nil {
		t.Fatalf("ClaimExecutionIdentity returned error: %v", err)
	}

	if vm.ScratchPath != workspacePath {
		t.Fatalf("ScratchPath = %q, want persistent workspace path %q", vm.ScratchPath, workspacePath)
	}
	if vm.UUID != execID || vm.CgroupID != execID {
		t.Fatalf("unexpected execution identity after persistent claim: UUID=%q CgroupID=%q want %q", vm.UUID, vm.CgroupID, execID)
	}
}
