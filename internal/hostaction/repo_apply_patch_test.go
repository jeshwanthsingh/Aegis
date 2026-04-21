package hostaction

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	patch := gitOutput(t, repoRoot, "diff", "--", relPath)
	if patch == "" {
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
