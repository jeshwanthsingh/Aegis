package hostaction

import (
	"context"

	"aegis/internal/approval"
)

const (
	EnvRepoRootsJSON = "AEGIS_HOST_REPOS_JSON"

	MaxPatchBytes        = 256 * 1024
	MaxAffectedFiles     = 64
	MaxRelativePathBytes = 256
	MaxPatchLines        = 10000
)

type Class string

const (
	ClassRepoApplyPatchV1 Class = "repo_apply_patch_v1"

	ClassHostFileDeleteV1     Class = "host_file_delete_v1"
	ClassHostConfigMoveV1     Class = "host_config_move_v1"
	ClassHostPackageManagerV1 Class = "host_package_manager_v1"
	ClassHostDockerSocketV1   Class = "host_docker_socket_v1"
	ClassHostSystemResourceV1 Class = "host_system_resource_v1"
)

type Request struct {
	Class          Class                  `json:"class"`
	RepoApplyPatch *RepoApplyPatchRequest `json:"repo_apply_patch,omitempty"`
}

type RepoApplyPatchRequest struct {
	RepoLabel    string   `json:"repo_label"`
	PatchBase64  string   `json:"patch_base64"`
	TargetScope  []string `json:"target_scope,omitempty"`
	BaseRevision string   `json:"base_revision"`
}

type Response struct {
	Class          Class                   `json:"class,omitempty"`
	RepoApplyPatch *RepoApplyPatchResponse `json:"repo_apply_patch,omitempty"`
}

type RepoApplyPatchResponse struct {
	RepoLabel       string   `json:"repo_label"`
	AppliedPaths    []string `json:"applied_paths,omitempty"`
	PatchDigest     string   `json:"patch_digest"`
	PatchDigestAlgo string   `json:"patch_digest_algo"`
	BaseRevision    string   `json:"base_revision"`
}

type RepoBinding struct {
	Label string
	Root  string
}

type CanonicalRequest struct {
	Class              Class
	Resource           approval.Resource
	ResourceDigest     string
	ResourceDigestAlgo string
	Evidence           *Evidence
	RepoApplyPatch     *CanonicalRepoApplyPatch
}

type CanonicalRepoApplyPatch struct {
	Repo            RepoBinding
	Patch           []byte
	TargetScope     []string
	AffectedPaths   []string
	PatchDigest     string
	PatchDigestAlgo string
	BaseRevision    string
}

type Evidence struct {
	Class          Class                   `json:"class"`
	RepoApplyPatch *RepoApplyPatchEvidence `json:"repo_apply_patch,omitempty"`
}

type RepoApplyPatchEvidence struct {
	RepoLabel       string   `json:"repo_label"`
	TargetScope     []string `json:"target_scope,omitempty"`
	AffectedPaths   []string `json:"affected_paths"`
	PatchDigest     string   `json:"patch_digest"`
	PatchDigestAlgo string   `json:"patch_digest_algo"`
	BaseRevision    string   `json:"base_revision"`
}

type RepoResolver interface {
	ResolveRepo(ctx context.Context, label string) (RepoBinding, error)
}

type Prepared interface {
	Apply(ctx context.Context) (Response, error)
	Release()
}

type Preparer interface {
	Prepare(ctx context.Context, req CanonicalRequest) (Prepared, error)
}
