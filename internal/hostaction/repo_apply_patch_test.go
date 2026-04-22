package hostaction

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func gitOutputRaw(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
	return string(output)
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func makeGitRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitOutput(t, dir, "init")
	gitOutput(t, dir, "config", "user.email", "aegis@example.com")
	gitOutput(t, dir, "config", "user.name", "Aegis Test")
	writeFile(t, filepath.Join(dir, "README.md"), "hello\n")
	gitOutput(t, dir, "add", "README.md")
	gitOutput(t, dir, "commit", "-m", "init")
	return dir, gitOutput(t, dir, "rev-parse", "HEAD")
}

func makePatch(t *testing.T, repoRoot string, relPath string, newBody string) string {
	t.Helper()
	fullPath := filepath.Join(repoRoot, filepath.FromSlash(relPath))
	writeFile(t, fullPath, newBody)
	patch := gitOutputRaw(t, repoRoot, "diff", "--", relPath)
	if strings.TrimSpace(patch) == "" {
		t.Fatalf("git diff produced empty patch for %s", relPath)
	}
	gitOutput(t, repoRoot, "checkout", "--", relPath)
	return patch
}

func patchRequest(repoLabel string, patch string, baseRevision string) Request {
	return Request{
		Class: ClassRepoApplyPatchV1,
		RepoApplyPatch: &RepoApplyPatchRequest{
			RepoLabel:    repoLabel,
			PatchBase64:  base64.StdEncoding.EncodeToString([]byte(patch)),
			BaseRevision: baseRevision,
		},
	}
}

func mustStaticResolver(t *testing.T, bindings map[string]string) *StaticRepoResolver {
	t.Helper()
	resolver, err := NewStaticRepoResolver(bindings)
	if err != nil {
		t.Fatalf("NewStaticRepoResolver: %v", err)
	}
	return resolver
}

func requireRuleID(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want)
	}
	var typed *Error
	if !AsError(err, &typed) {
		t.Fatalf("expected hostaction.Error, got %T: %v", err, err)
	}
	if typed.RuleID != want {
		t.Fatalf("rule id = %q, want %q (detail=%q)", typed.RuleID, want, typed.Detail)
	}
}

func TestCanonicalizeRequestRejectsPathTraversal(t *testing.T) {
	patch := strings.Join([]string{
		"diff --git a/../evil.txt b/../evil.txt",
		"--- a/../evil.txt",
		"+++ b/../evil.txt",
		"@@ -1 +1 @@",
		"-old",
		"+new",
		"",
	}, "\n")
	_, err := CanonicalizeRequest(patchRequest("demo", patch, "base"))
	requireRuleID(t, err, "broker.host_action_path_escape")
}

func TestCanonicalizeRequestRejectsInvalidAndUnsupportedPatchShapes(t *testing.T) {
	t.Run("invalid_format", func(t *testing.T) {
		_, err := CanonicalizeRequest(patchRequest("demo", "not a unified diff", "base"))
		requireRuleID(t, err, "broker.host_action_patch_invalid")
	})

	t.Run("delete_not_supported", func(t *testing.T) {
		patch := strings.Join([]string{
			"diff --git a/README.md b/README.md",
			"deleted file mode 100644",
			"--- a/README.md",
			"+++ /dev/null",
			"@@ -1 +0,0 @@",
			"-hello",
			"",
		}, "\n")
		_, err := CanonicalizeRequest(patchRequest("demo", patch, "base"))
		requireRuleID(t, err, "broker.host_action_patch_unsupported")
	})
}

func TestCanonicalizeRequestEnforcesPatchLimits(t *testing.T) {
	t.Run("patch_size", func(t *testing.T) {
		raw := strings.Repeat("a", MaxPatchBytes+1)
		_, err := CanonicalizeRequest(patchRequest("demo", raw, "base"))
		requireRuleID(t, err, "broker.host_action_patch_too_large")
	})

	t.Run("affected_file_count", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < MaxAffectedFiles+1; i++ {
			fmt.Fprintf(&b, "diff --git a/file-%03d.txt b/file-%03d.txt\n", i, i)
			fmt.Fprintf(&b, "--- a/file-%03d.txt\n", i)
			fmt.Fprintf(&b, "+++ b/file-%03d.txt\n", i)
			b.WriteString("@@ -1 +1 @@\n-old\n+new\n")
		}
		_, err := CanonicalizeRequest(patchRequest("demo", b.String(), "base"))
		requireRuleID(t, err, "broker.host_action_patch_too_many_files")
	})

	t.Run("relative_path_length", func(t *testing.T) {
		longPath := strings.Repeat("a", MaxRelativePathBytes+1)
		patch := strings.Join([]string{
			"diff --git a/" + longPath + " b/" + longPath,
			"--- a/" + longPath,
			"+++ b/" + longPath,
			"@@ -1 +1 @@",
			"-old",
			"+new",
			"",
		}, "\n")
		_, err := CanonicalizeRequest(patchRequest("demo", patch, "base"))
		requireRuleID(t, err, "broker.host_action_path_too_long")
	})
}

func TestRepoPatchPreparerRejectsBaseRevisionMismatch(t *testing.T) {
	repoRoot, baseRevision := makeGitRepo(t)
	patch := makePatch(t, repoRoot, "README.md", "hello world\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, strings.Repeat("a", len(baseRevision))))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	_, err = preparer.Prepare(context.Background(), canonical)
	requireRuleID(t, err, "broker.host_action_base_revision_mismatch")
}

func TestRepoPatchPreparerRejectsDirtyScope(t *testing.T) {
	repoRoot, baseRevision := makeGitRepo(t)
	patch := makePatch(t, repoRoot, "README.md", "hello world\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, baseRevision))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	writeFile(t, filepath.Join(repoRoot, "README.md"), "dirty\n")
	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	_, err = preparer.Prepare(context.Background(), canonical)
	requireRuleID(t, err, "broker.host_action_dirty_scope")
}

func TestRepoPatchPreparerRejectsSymlinkEscape(t *testing.T) {
	repoRoot, baseRevision := makeGitRepo(t)
	targetDir := filepath.Join(repoRoot, "real")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(targetDir): %v", err)
	}
	if err := os.Symlink(targetDir, filepath.Join(repoRoot, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	patch := strings.Join([]string{
		"diff --git a/link/file.txt b/link/file.txt",
		"--- a/link/file.txt",
		"+++ b/link/file.txt",
		"@@ -1 +1 @@",
		"-old",
		"+new",
		"",
	}, "\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, baseRevision))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	_, err = preparer.Prepare(context.Background(), canonical)
	requireRuleID(t, err, "broker.host_action_symlink_escape")
}

func TestRepoPatchPreparerAppliesPatchUnderLock(t *testing.T) {
	repoRoot, baseRevision := makeGitRepo(t)
	patch := makePatch(t, repoRoot, "README.md", "hello world\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, baseRevision))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	originalLockDir := repoLockDirPath
	repoLockDirPath = t.TempDir()
	t.Cleanup(func() { repoLockDirPath = originalLockDir })

	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	prepared, err := preparer.Prepare(context.Background(), canonical)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer prepared.Release()

	resp, err := prepared.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if resp.RepoApplyPatch == nil || resp.RepoApplyPatch.RepoLabel != "demo" {
		t.Fatalf("response = %+v", resp)
	}
	if got := gitOutput(t, repoRoot, "show", "HEAD:README.md"); got != "hello" {
		t.Fatalf("HEAD content changed unexpectedly: %q", got)
	}
	actual, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README): %v", err)
	}
	if string(actual) != "hello world\n" {
		t.Fatalf("working tree content = %q", string(actual))
	}
}

func TestRepoPatchPreparerLockFailureIsClean(t *testing.T) {
	repoRoot, baseRevision := makeGitRepo(t)
	patch := makePatch(t, repoRoot, "README.md", "hello world\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, baseRevision))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	lockFilePath := filepath.Join(t.TempDir(), "lock-file")
	if err := os.WriteFile(lockFilePath, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("WriteFile(lock-file): %v", err)
	}
	originalLockDir := repoLockDirPath
	repoLockDirPath = lockFilePath
	t.Cleanup(func() { repoLockDirPath = originalLockDir })

	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	_, err = preparer.Prepare(context.Background(), canonical)
	requireRuleID(t, err, "broker.host_action_lock_unavailable")
	actual, readErr := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if readErr != nil {
		t.Fatalf("ReadFile(README): %v", readErr)
	}
	if string(actual) != "hello\n" {
		t.Fatalf("working tree content = %q", string(actual))
	}
}

func TestRepoPatchPreparerRespectsCrossProcessLock(t *testing.T) {
	if os.Getenv("AEGIS_TEST_HOLDS_HOSTACTION_LOCK") == "1" {
		repoLockDirPath = os.Getenv("AEGIS_TEST_HOSTACTION_LOCK_DIR")
		unlock, err := acquireRepoLock(context.Background(), os.Getenv("AEGIS_TEST_HOSTACTION_LOCK_REPO"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "acquireRepoLock: %v\n", err)
			os.Exit(2)
		}
		defer unlock()
		if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
			fmt.Fprintf(os.Stderr, "write ready: %v\n", err)
			os.Exit(2)
		}
		_, _ = io.ReadAll(os.Stdin)
		os.Exit(0)
	}

	repoRoot, baseRevision := makeGitRepo(t)
	patch := makePatch(t, repoRoot, "README.md", "hello world\n")
	canonical, err := CanonicalizeRequest(patchRequest("demo", patch, baseRevision))
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	lockDir := t.TempDir()
	originalLockDir := repoLockDirPath
	repoLockDirPath = lockDir
	t.Cleanup(func() { repoLockDirPath = originalLockDir })

	cmd := exec.Command(os.Args[0], "-test.run=TestRepoPatchPreparerRespectsCrossProcessLock")
	cmd.Env = append(os.Environ(),
		"AEGIS_TEST_HOLDS_HOSTACTION_LOCK=1",
		"AEGIS_TEST_HOSTACTION_LOCK_DIR="+lockDir,
		"AEGIS_TEST_HOSTACTION_LOCK_REPO="+repoRoot,
	)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start(helper): %v", err)
	}
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, 6)
		_, err := io.ReadFull(stdoutPipe, buf)
		if err == nil && string(buf) != "ready\n" {
			err = fmt.Errorf("unexpected helper readiness %q", string(buf))
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("helper readiness: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for helper readiness")
	}

	preparer := NewRepoPatchPreparer(mustStaticResolver(t, map[string]string{"demo": repoRoot}))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = preparer.Prepare(ctx, canonical)
	requireRuleID(t, err, "broker.host_action_lock_unavailable")

	_ = stdinPipe.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper wait: %v", err)
	}
}
