package executor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceDiskPathRejectsTraversal(t *testing.T) {
	origDir := workspaceDir
	workspaceDir = t.TempDir()
	t.Cleanup(func() { workspaceDir = origDir })

	for _, raw := range []string{"../escape", "..\\escape", "with/slash", "with\\slash", "space bad", ".hidden"} {
		if _, err := workspaceDiskPath(raw); !errors.Is(err, ErrInvalidWorkspaceID) {
			t.Fatalf("workspaceDiskPath(%q) err = %v, want ErrInvalidWorkspaceID", raw, err)
		}
	}
}

func TestGetOrCreateWorkspaceCreatesRegularDisk(t *testing.T) {
	origDir := workspaceDir
	origMkfs := runMkfsExt4Cmd
	workspaceDir = t.TempDir()
	runMkfsExt4Cmd = func(path string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		workspaceDir = origDir
		runMkfsExt4Cmd = origMkfs
	})

	path, err := GetOrCreateWorkspace("demo-workspace", 1)
	if err != nil {
		t.Fatalf("GetOrCreateWorkspace returned error: %v", err)
	}
	if filepath.Dir(path) != workspaceDir {
		t.Fatalf("workspace path dir = %q, want %q", filepath.Dir(path), workspaceDir)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat workspace: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("workspace mode = %v, want regular file", info.Mode())
	}
	if got, want := info.Size(), int64(1024*1024); got != want {
		t.Fatalf("workspace size = %d, want %d", got, want)
	}
}

func TestCreateWorkspaceThenGetWorkspace(t *testing.T) {
	origDir := workspaceDir
	origMkfs := runMkfsExt4Cmd
	workspaceDir = t.TempDir()
	runMkfsExt4Cmd = func(path string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		workspaceDir = origDir
		runMkfsExt4Cmd = origMkfs
	})

	created, err := CreateWorkspace("demo-workspace", 1)
	if err != nil {
		t.Fatalf("CreateWorkspace returned error: %v", err)
	}
	got, err := GetWorkspace("demo-workspace")
	if err != nil {
		t.Fatalf("GetWorkspace returned error: %v", err)
	}
	if got != created {
		t.Fatalf("workspace path = %q, want %q", got, created)
	}
}

func TestGetWorkspaceMissing(t *testing.T) {
	origDir := workspaceDir
	workspaceDir = t.TempDir()
	t.Cleanup(func() { workspaceDir = origDir })

	if _, err := GetWorkspace("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GetWorkspace err = %v, want os.ErrNotExist", err)
	}
}

func TestCreateWorkspaceDuplicate(t *testing.T) {
	origDir := workspaceDir
	origMkfs := runMkfsExt4Cmd
	workspaceDir = t.TempDir()
	runMkfsExt4Cmd = func(path string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		workspaceDir = origDir
		runMkfsExt4Cmd = origMkfs
	})

	if _, err := CreateWorkspace("demo-workspace", 1); err != nil {
		t.Fatalf("CreateWorkspace returned error: %v", err)
	}
	if _, err := CreateWorkspace("demo-workspace", 1); !errors.Is(err, ErrWorkspaceExists) {
		t.Fatalf("CreateWorkspace duplicate err = %v, want ErrWorkspaceExists", err)
	}
}

func TestGetOrCreateWorkspaceRejectsExistingSymlink(t *testing.T) {
	origDir := workspaceDir
	origMkfs := runMkfsExt4Cmd
	workspaceDir = t.TempDir()
	runMkfsExt4Cmd = func(path string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		workspaceDir = origDir
		runMkfsExt4Cmd = origMkfs
	})

	target := filepath.Join(workspaceDir, "target.ext4")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	link := filepath.Join(workspaceDir, "demo.ext4")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, err := GetOrCreateWorkspace("demo", 1); err == nil {
		t.Fatal("GetOrCreateWorkspace unexpectedly succeeded for symlink")
	}
}

func TestDeleteWorkspaceRejectsTraversal(t *testing.T) {
	origDir := workspaceDir
	workspaceDir = t.TempDir()
	t.Cleanup(func() { workspaceDir = origDir })

	if err := DeleteWorkspace("../escape"); !errors.Is(err, ErrInvalidWorkspaceID) {
		t.Fatalf("DeleteWorkspace err = %v, want ErrInvalidWorkspaceID", err)
	}
}
