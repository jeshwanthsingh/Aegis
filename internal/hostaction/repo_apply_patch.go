package hostaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"aegis/internal/approval"
)

var runGitCommand = func(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return output, err
		}
		return output, fmt.Errorf("%w: %s", err, trimmed)
	}
	return output, nil
}

var repoLocks sync.Map

type RepoPatchPreparer struct {
	Resolver RepoResolver
}

type preparedRepoApplyPatch struct {
	req      CanonicalRequest
	repoRoot string
	unlock   func()
}

func NewRepoPatchPreparer(resolver RepoResolver) *RepoPatchPreparer {
	return &RepoPatchPreparer{Resolver: resolver}
}

func CanonicalizeRequest(req Request) (CanonicalRequest, error) {
	switch req.Class {
	case ClassRepoApplyPatchV1:
		if req.RepoApplyPatch == nil {
			return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", nil, "repo_apply_patch payload is required")
		}
		return canonicalizeRepoApplyPatch(*req.RepoApplyPatch)
	default:
		return CanonicalRequest{}, errorf("broker.host_action_unsupported", map[string]string{"host_action_class": string(req.Class)}, "host action class %q is not supported", req.Class)
	}
}

func (p *RepoPatchPreparer) Prepare(ctx context.Context, req CanonicalRequest) (Prepared, error) {
	if req.Class != ClassRepoApplyPatchV1 || req.RepoApplyPatch == nil {
		return nil, errorf("broker.host_action_unsupported", nil, "host action class %q is not supported", req.Class)
	}
	if p == nil || p.Resolver == nil {
		return nil, errorf("broker.host_action_unsupported", map[string]string{"host_action_class": string(req.Class)}, "host action support is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	repo, err := p.Resolver.ResolveRepo(ctx, req.RepoApplyPatch.Repo.Label)
	if err != nil {
		return nil, err
	}
	lock := repoLock(repo.Root)
	lock.Lock()
	prepared := &preparedRepoApplyPatch{
		req:      req,
		repoRoot: repo.Root,
		unlock:   lock.Unlock,
	}
	if err := prepared.precheck(ctx); err != nil {
		prepared.Release()
		return nil, err
	}
	return prepared, nil
}

func (p *preparedRepoApplyPatch) Apply(ctx context.Context) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	patch := p.req.RepoApplyPatch
	if patch == nil {
		return Response{}, fmt.Errorf("host patch request is missing")
	}
	if _, err := runGitCommand(ctx, p.repoRoot, patch.Patch, "apply", "--whitespace=nowarn", "-"); err != nil {
		return Response{}, fmt.Errorf("apply patch: %w", err)
	}
	return Response{
		Class: ClassRepoApplyPatchV1,
		RepoApplyPatch: &RepoApplyPatchResponse{
			RepoLabel:       patch.Repo.Label,
			AppliedPaths:    append([]string(nil), patch.AffectedPaths...),
			PatchDigest:     patch.PatchDigest,
			PatchDigestAlgo: patch.PatchDigestAlgo,
			BaseRevision:    patch.BaseRevision,
		},
	}, nil
}

func (p *preparedRepoApplyPatch) Release() {
	if p == nil || p.unlock == nil {
		return
	}
	p.unlock()
	p.unlock = nil
}

func (p *preparedRepoApplyPatch) precheck(ctx context.Context) error {
	patch := p.req.RepoApplyPatch
	if patch == nil {
		return errorf("broker.host_action_patch_invalid", nil, "host patch request is missing")
	}
	root, err := verifyGitWorktree(ctx, p.repoRoot)
	if err != nil {
		return err
	}
	p.repoRoot = root
	if err := verifyBaseRevision(ctx, root, patch.BaseRevision); err != nil {
		return err
	}
	if err := validateTargetScope(p.repoRoot, patch.TargetScope, patch.AffectedPaths); err != nil {
		return err
	}
	if err := validateNoSymlinkComponents(p.repoRoot, patch.AffectedPaths); err != nil {
		return err
	}
	if err := ensureCleanScope(ctx, p.repoRoot, patch.AffectedPaths); err != nil {
		return err
	}
	if err := checkPatchApplies(ctx, p.repoRoot, patch.Patch); err != nil {
		return err
	}
	return nil
}

func canonicalizeRepoApplyPatch(req RepoApplyPatchRequest) (CanonicalRequest, error) {
	repoLabel := strings.ToLower(strings.TrimSpace(req.RepoLabel))
	if repoLabel == "" {
		return CanonicalRequest{}, errorf("broker.host_action_repo_root_mismatch", nil, "repo label is required")
	}
	if strings.TrimSpace(req.PatchBase64) == "" {
		return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", map[string]string{"repo_label": repoLabel}, "patch payload is required")
	}
	patch, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PatchBase64))
	if err != nil {
		return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", map[string]string{"repo_label": repoLabel}, "decode patch payload: %v", err)
	}
	if len(patch) == 0 {
		return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", map[string]string{"repo_label": repoLabel}, "patch payload is empty")
	}
	if len(patch) > MaxPatchBytes {
		return CanonicalRequest{}, errorf("broker.host_action_patch_too_large", map[string]string{"repo_label": repoLabel}, "patch payload exceeds %d bytes", MaxPatchBytes)
	}
	if bytes.Count(patch, []byte{'\n'})+1 > MaxPatchLines {
		return CanonicalRequest{}, errorf("broker.host_action_patch_too_many_lines", map[string]string{"repo_label": repoLabel}, "patch payload exceeds %d lines", MaxPatchLines)
	}
	if bytes.IndexByte(patch, 0) >= 0 {
		return CanonicalRequest{}, errorf("broker.host_action_patch_unsupported", map[string]string{"repo_label": repoLabel}, "binary patch payloads are not supported")
	}
	affectedPaths, err := parseUnifiedDiffPaths(patch)
	if err != nil {
		return CanonicalRequest{}, err
	}
	targetScope, err := canonicalizeTargetScopeValues(req.TargetScope)
	if err != nil {
		return CanonicalRequest{}, err
	}
	baseRevision := strings.TrimSpace(req.BaseRevision)
	if baseRevision == "" {
		return CanonicalRequest{}, errorf("broker.host_action_base_revision_mismatch", map[string]string{"repo_label": repoLabel}, "base_revision is required")
	}
	patchDigest := digestBytes(patch)
	resource, err := approval.CanonicalizeResource(approval.Resource{
		Kind: approval.ResourceKindHostRepoApplyPatchV1,
		HostRepoApplyPatch: &approval.HostRepoApplyPatchResource{
			RepoLabel:       repoLabel,
			TargetScope:     append([]string(nil), targetScope...),
			AffectedPaths:   append([]string(nil), affectedPaths...),
			PatchDigest:     patchDigest,
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    baseRevision,
		},
	})
	if err != nil {
		return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", map[string]string{"repo_label": repoLabel}, "canonicalize host patch resource: %v", err)
	}
	resourceDigest, resourceDigestAlgo, err := approval.DigestResource(resource)
	if err != nil {
		return CanonicalRequest{}, errorf("broker.host_action_patch_invalid", map[string]string{"repo_label": repoLabel}, "digest host patch resource: %v", err)
	}
	evidence := &Evidence{
		Class: ClassRepoApplyPatchV1,
		RepoApplyPatch: &RepoApplyPatchEvidence{
			RepoLabel:       repoLabel,
			TargetScope:     append([]string(nil), targetScope...),
			AffectedPaths:   append([]string(nil), affectedPaths...),
			PatchDigest:     patchDigest,
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    baseRevision,
		},
	}
	return CanonicalRequest{
		Class:              ClassRepoApplyPatchV1,
		Resource:           resource,
		ResourceDigest:     resourceDigest,
		ResourceDigestAlgo: resourceDigestAlgo,
		Evidence:           evidence,
		RepoApplyPatch: &CanonicalRepoApplyPatch{
			Repo: RepoBinding{
				Label: repoLabel,
			},
			Patch:           append([]byte(nil), patch...),
			TargetScope:     append([]string(nil), targetScope...),
			AffectedPaths:   append([]string(nil), affectedPaths...),
			PatchDigest:     patchDigest,
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    baseRevision,
		},
	}, nil
}

func parseUnifiedDiffPaths(patch []byte) ([]string, error) {
	type patchFile struct {
		oldPath string
		newPath string
		sawHunk bool
	}
	var (
		current patchFile
		seen    = map[string]struct{}{}
		paths   []string
	)
	finalize := func() error {
		if current.oldPath == "" && current.newPath == "" && !current.sawHunk {
			return nil
		}
		if current.oldPath == "" || current.newPath == "" {
			return errorf("broker.host_action_patch_invalid", nil, "patch file headers are incomplete")
		}
		if current.oldPath != current.newPath {
			return errorf("broker.host_action_patch_unsupported", map[string]string{"old_path": current.oldPath, "new_path": current.newPath}, "rename and copy patch entries are not supported")
		}
		if !current.sawHunk {
			return errorf("broker.host_action_patch_invalid", map[string]string{"path": current.newPath}, "patch for %s has no hunks", current.newPath)
		}
		if _, ok := seen[current.newPath]; !ok {
			seen[current.newPath] = struct{}{}
			paths = append(paths, current.newPath)
		}
		current = patchFile{}
		return nil
	}
	for _, rawLine := range bytes.Split(patch, []byte("\n")) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if err := finalize(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "rename from "),
			strings.HasPrefix(line, "rename to "),
			strings.HasPrefix(line, "copy from "),
			strings.HasPrefix(line, "copy to "),
			strings.HasPrefix(line, "old mode "),
			strings.HasPrefix(line, "new mode "),
			strings.HasPrefix(line, "deleted file mode "),
			strings.HasPrefix(line, "new file mode "),
			strings.HasPrefix(line, "similarity index "),
			strings.HasPrefix(line, "dissimilarity index "),
			strings.HasPrefix(line, "GIT binary patch"),
			strings.HasPrefix(line, "Binary files "):
			return nil, errorf("broker.host_action_patch_unsupported", nil, "patch contains an unsupported feature")
		case strings.HasPrefix(line, "--- "):
			value, err := parsePatchHeaderPath(strings.TrimSpace(strings.TrimPrefix(line, "--- ")))
			if err != nil {
				return nil, err
			}
			current.oldPath = value
		case strings.HasPrefix(line, "+++ "):
			value, err := parsePatchHeaderPath(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")))
			if err != nil {
				return nil, err
			}
			current.newPath = value
		case strings.HasPrefix(line, "@@ "):
			if current.oldPath == "" || current.newPath == "" {
				return nil, errorf("broker.host_action_patch_invalid", nil, "patch hunk header appeared before file headers")
			}
			current.sawHunk = true
		}
	}
	if err := finalize(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errorf("broker.host_action_patch_invalid", nil, "patch contains no supported file changes")
	}
	if len(paths) > MaxAffectedFiles {
		return nil, errorf("broker.host_action_patch_too_many_files", map[string]string{"affected_file_count": strconv.Itoa(len(paths))}, "patch touches %d files; limit is %d", len(paths), MaxAffectedFiles)
	}
	sort.Strings(paths)
	return paths, nil
}

func parsePatchHeaderPath(raw string) (string, error) {
	value := raw
	if idx := strings.IndexByte(value, '\t'); idx >= 0 {
		value = value[:idx]
	}
	value = strings.TrimSpace(value)
	if value == "/dev/null" {
		return "", errorf("broker.host_action_patch_unsupported", nil, "file creation and deletion patches are not supported")
	}
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", errorf("broker.host_action_patch_invalid", nil, "quoted patch path is invalid")
		}
		value = unquoted
	}
	switch {
	case strings.HasPrefix(value, "a/"), strings.HasPrefix(value, "b/"):
		value = value[2:]
	}
	return sanitizeRelativePath(value)
}

func canonicalizeTargetScopeValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	seen := map[string]struct{}{}
	scopes := make([]string, 0, len(values))
	for _, raw := range values {
		value, err := sanitizeRelativePath(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		scopes = append(scopes, value)
	}
	sort.Strings(scopes)
	return scopes, nil
}

func sanitizeRelativePath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errorf("broker.host_action_path_escape", nil, "relative path is required")
	}
	if strings.Contains(value, "\\") {
		return "", errorf("broker.host_action_path_escape", map[string]string{"path": value}, "backslash path separators are not supported")
	}
	if strings.HasPrefix(value, "/") {
		return "", errorf("broker.host_action_path_escape", map[string]string{"path": value}, "absolute paths are not allowed")
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == "" {
		return "", errorf("broker.host_action_path_escape", map[string]string{"path": value}, "empty relative paths are not allowed")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errorf("broker.host_action_path_escape", map[string]string{"path": value}, "path traversal is not allowed")
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == ".git" {
			return "", errorf("broker.host_action_patch_unsupported", map[string]string{"path": value}, ".git paths are not supported")
		}
	}
	if len(cleaned) > MaxRelativePathBytes {
		return "", errorf("broker.host_action_path_too_long", map[string]string{"path": cleaned}, "path %q exceeds %d bytes", cleaned, MaxRelativePathBytes)
	}
	return cleaned, nil
}

func verifyGitWorktree(ctx context.Context, repoRoot string) (string, error) {
	output, err := runGitCommand(ctx, repoRoot, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errorf("broker.host_action_repo_root_mismatch", nil, "repo root is not a git worktree: %v", err)
	}
	root := filepath.Clean(strings.TrimSpace(string(output)))
	want := filepath.Clean(repoRoot)
	if root != want {
		return "", errorf("broker.host_action_repo_root_mismatch", map[string]string{"repo_root": filepath.Base(want)}, "configured repo root does not match the git worktree root")
	}
	return root, nil
}

func verifyBaseRevision(ctx context.Context, repoRoot string, baseRevision string) error {
	output, err := runGitCommand(ctx, repoRoot, nil, "rev-parse", "HEAD")
	if err != nil {
		return errorf("broker.host_action_base_revision_mismatch", nil, "resolve HEAD: %v", err)
	}
	head := strings.TrimSpace(string(output))
	if head != strings.TrimSpace(baseRevision) {
		return errorf("broker.host_action_base_revision_mismatch", map[string]string{"expected_base_revision": strings.TrimSpace(baseRevision), "observed_head": head}, "repo HEAD does not match base_revision")
	}
	return nil
}

func validateTargetScope(repoRoot string, targetScope []string, affectedPaths []string) error {
	for _, rel := range affectedPaths {
		full := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if !isWithinRoot(repoRoot, full) {
			return errorf("broker.host_action_path_escape", map[string]string{"path": rel}, "path %q escapes the repo root", rel)
		}
		if len(targetScope) > 0 && !pathWithinScope(rel, targetScope) {
			return errorf("broker.host_action_path_escape", map[string]string{"path": rel}, "path %q is outside target_scope", rel)
		}
	}
	return nil
}

func validateNoSymlinkComponents(repoRoot string, affectedPaths []string) error {
	for _, rel := range affectedPaths {
		current := filepath.Clean(repoRoot)
		for _, part := range strings.Split(rel, "/") {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				if os.IsNotExist(err) {
					break
				}
				return errorf("broker.host_action_symlink_escape", map[string]string{"path": rel}, "stat path %q: %v", rel, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errorf("broker.host_action_symlink_escape", map[string]string{"path": rel}, "symlinked path components are not supported")
			}
		}
	}
	return nil
}

func ensureCleanScope(ctx context.Context, repoRoot string, affectedPaths []string) error {
	args := []string{"status", "--porcelain", "--untracked-files=all", "--"}
	args = append(args, affectedPaths...)
	output, err := runGitCommand(ctx, repoRoot, nil, args...)
	if err != nil {
		return errorf("broker.host_action_patch_precondition_failed", nil, "check repo status: %v", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		return errorf("broker.host_action_dirty_scope", map[string]string{"affected_file_count": strconv.Itoa(len(affectedPaths))}, "affected paths are not clean")
	}
	return nil
}

func checkPatchApplies(ctx context.Context, repoRoot string, patch []byte) error {
	if _, err := runGitCommand(ctx, repoRoot, patch, "apply", "--check", "--whitespace=nowarn", "-"); err != nil {
		return errorf("broker.host_action_patch_precondition_failed", nil, "git apply --check failed: %v", err)
	}
	return nil
}

func pathWithinScope(rel string, scopes []string) bool {
	for _, scope := range scopes {
		if rel == scope || strings.HasPrefix(rel, scope+"/") {
			return true
		}
	}
	return false
}

func isWithinRoot(root string, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func repoLock(root string) *sync.Mutex {
	lock, _ := repoLocks.LoadOrStore(filepath.Clean(root), &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
