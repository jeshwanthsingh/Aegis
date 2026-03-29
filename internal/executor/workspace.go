package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const WorkspacesDir = "/tmp/aegis/workspaces"

func InitWorkspacesDir() error {
	if err := os.MkdirAll(WorkspacesDir, 0o755); err != nil {
		return fmt.Errorf("create workspaces dir: %w", err)
	}
	return nil
}

func GetOrCreateWorkspace(workspaceID string, sizeMB int) (string, error) {
	if workspaceID == "" {
		return "", fmt.Errorf("workspace ID is required")
	}
	if err := InitWorkspacesDir(); err != nil {
		return "", err
	}

	path := filepath.Join(WorkspacesDir, workspaceID+".ext4")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat workspace disk: %w", err)
	}

	if err := createExt4Disk(path, sizeMB); err != nil {
		return "", err
	}
	return path, nil
}

func DeleteWorkspace(workspaceID string) error {
	if workspaceID == "" {
		return fmt.Errorf("workspace ID is required")
	}
	path := filepath.Join(WorkspacesDir, workspaceID+".ext4")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete workspace %s: %w", workspaceID, err)
	}
	return nil
}

func createExt4Disk(path string, sizeMB int) error {
	cmd := exec.Command("dd", "if=/dev/zero", fmt.Sprintf("of=%s", path), "bs=1M", fmt.Sprintf("count=%d", sizeMB))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dd: %w: %s", err, string(output))
	}

	cmd = exec.Command("/usr/sbin/mkfs.ext4", "-F", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, string(output))
	}

	return nil
}
