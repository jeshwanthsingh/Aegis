package executor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

const WorkspacesDir = "/tmp/aegis/workspaces"

var (
	ErrInvalidWorkspaceID = errors.New("invalid workspace ID")
	workspaceDir          = WorkspacesDir
	workspaceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	runMkfsExt4Cmd        = func(path string) ([]byte, error) {
		cmd := exec.Command("/usr/sbin/mkfs.ext4", "-F", path)
		return cmd.CombinedOutput()
	}
)

func InitWorkspacesDir() error {
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		return fmt.Errorf("create workspaces dir: %w", err)
	}
	if err := os.Chmod(workspaceDir, 0o700); err != nil {
		return fmt.Errorf("chmod workspaces dir: %w", err)
	}
	return nil
}

func GetOrCreateWorkspace(workspaceID string, sizeMB int) (string, error) {
	path, err := workspaceDiskPath(workspaceID)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("workspace disk is not a regular file")
		}
		return path, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat workspace disk: %w", err)
	}

	if err := createExt4Disk(path, sizeMB); err != nil {
		raceInfo, raceErr := os.Lstat(path)
		if raceErr == nil && raceInfo.Mode().IsRegular() {
			return path, nil
		}
		if raceErr != nil && !os.IsNotExist(raceErr) {
			return "", fmt.Errorf("stat workspace disk after create: %w", raceErr)
		}
		return "", err
	}
	return path, nil
}

func DeleteWorkspace(workspaceID string) error {
	path, err := workspaceDiskPath(workspaceID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete workspace %s: %w", workspaceID, err)
	}
	return nil
}

func createExt4Disk(path string, sizeMB int) error {
	if sizeMB <= 0 {
		return fmt.Errorf("workspace size must be positive")
	}
	tempFile, err := os.CreateTemp(workspaceDir, "workspace-*.ext4")
	if err != nil {
		return fmt.Errorf("create workspace disk: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = tempFile.Close()
	}()
	defer func() {
		if _, err := os.Stat(tempPath); err == nil {
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod workspace disk: %w", err)
	}
	if err := tempFile.Truncate(int64(sizeMB) * 1024 * 1024); err != nil {
		return fmt.Errorf("truncate workspace disk: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close workspace disk: %w", err)
	}

	if output, err := runMkfsExt4Cmd(tempPath); err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, string(output))
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("finalize workspace disk: %w", err)
	}

	return nil
}

func workspaceDiskPath(workspaceID string) (string, error) {
	if workspaceID == "" {
		return "", fmt.Errorf("workspace ID is required")
	}
	if !workspaceIDPattern.MatchString(workspaceID) {
		return "", ErrInvalidWorkspaceID
	}
	if err := InitWorkspacesDir(); err != nil {
		return "", err
	}
	return filepath.Join(workspaceDir, workspaceID+".ext4"), nil
}
