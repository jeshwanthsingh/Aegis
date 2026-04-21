package lease

import (
	"context"
	"crypto/ed25519"
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
)

const (
	LeaseVersion  = "v1"
	PredicateType = "https://aegis.dev/Lease/v1"

	EnvSigningSeed                = "AEGIS_LEASE_SIGNING_SEED_B64"
	EnvIssuer                     = "AEGIS_LEASE_ISSUER"
	EnvDefaultHTTPCountBudget     = "AEGIS_LEASE_DEFAULT_HTTP_COUNT_BUDGET"
	EnvDefaultHostPatchCountBudget = "AEGIS_LEASE_DEFAULT_HOST_PATCH_COUNT_BUDGET"

	DefaultIssuerName          = "local_orchestrator"
	DefaultHTTPCountBudget     = uint64(64)
	DefaultHostPatchCountBudget = uint64(8)
)

type ActionKind string

const (
	ActionKindHTTPRequest        ActionKind = "http_request"
	ActionKindHostRepoApplyPatch ActionKind = "host_repo_apply_patch"
)

type SelectorKind string

const (
	SelectorKindHTTPRequestV1        SelectorKind = "http_request_v1"
	SelectorKindHostRepoApplyPatchV1 SelectorKind = "host_repo_apply_patch_v1"
)

type BudgetKind string

const (
	BudgetKindCount BudgetKind = "count"
)

type WorkloadIdentity struct {
	Kind        string `json:"kind"`
	BootDigest  string `json:"boot_digest"`
	RootfsImage string `json:"rootfs_image"`
}

type TrustLimitations struct {
	ApprovalRequiredActionKinds []ActionKind `json:"approval_required_action_kinds,omitempty"`
}

type Lease struct {
	Version         string             `json:"version"`
	LeaseID         string             `json:"lease_id"`
	Issuer          string             `json:"issuer"`
	IssuedAt        time.Time          `json:"issued_at"`
	ExpiresAt       time.Time          `json:"expires_at"`
	ExecutionID     string             `json:"execution_id"`
	Workload        WorkloadIdentity   `json:"workload"`
	PolicyDigest    string             `json:"policy_digest"`
	AuthorityDigest string             `json:"authority_digest"`
	Grants          []Grant            `json:"grants"`
	TrustLimits     *TrustLimitations  `json:"trust_limitations,omitempty"`
}

type Grant struct {
	GrantID    string           `json:"grant_id"`
	ActionKind ActionKind       `json:"action_kind"`
	Selector   ResourceSelector `json:"selector"`
	Budget     Budget           `json:"budget"`
}

type ResourceSelector struct {
	Kind               SelectorKind                 `json:"kind"`
	HTTP               *HTTPRequestSelector         `json:"http,omitempty"`
	HostRepoApplyPatch *HostRepoApplyPatchSelector  `json:"host_repo_apply_patch,omitempty"`
}

type HTTPRequestSelector struct {
	Domain       string   `json:"domain"`
	Methods      []string `json:"methods,omitempty"`
	PathPrefixes []string `json:"path_prefixes,omitempty"`
}

type HostRepoApplyPatchSelector struct {
	RepoLabel   string   `json:"repo_label"`
	TargetScope []string `json:"target_scope,omitempty"`
}

type Budget struct {
	Kind       BudgetKind `json:"kind"`
	LimitCount uint64     `json:"limit_count"`
}

type Statement struct {
	Type          string                  `json:"_type"`
	Subject       []dsse.StatementSubject `json:"subject"`
	PredicateType string                  `json:"predicateType"`
	Predicate     Lease                   `json:"predicate"`
}

type SignedLease struct {
	Envelope  dsse.Envelope `json:"envelope"`
	Statement Statement     `json:"statement"`
}

type BudgetDefaults struct {
	HTTPCount      uint64
	HostPatchCount uint64
}

type VerificationRequest struct {
	ExecutionID     string
	PolicyDigest    string
	AuthorityDigest string
	ActionKind      ActionKind
	Resource        approval.Resource
	Now             time.Time
}

type VerifiedLease struct {
	Lease              Lease
	IssuerKeyID        string
	Grant              Grant
	SelectorDigest     string
	SelectorDigestAlgo string
}

type CheckResult string

const (
	CheckVerified          CheckResult = "verified"
	CheckMissing           CheckResult = "missing"
	CheckExpired           CheckResult = "expired"
	CheckMalformed         CheckResult = "malformed"
	CheckSignatureInvalid  CheckResult = "signature_invalid"
	CheckExecutionMismatch CheckResult = "execution_id_mismatch"
	CheckPolicyMismatch    CheckResult = "policy_digest_mismatch"
	CheckAuthorityMismatch CheckResult = "authority_digest_mismatch"
	CheckActionMismatch    CheckResult = "action_kind_mismatch"
	CheckResourceMismatch  CheckResult = "resource_selector_mismatch"
	CheckUnavailable       CheckResult = "unavailable"
)

type BudgetResult string

const (
	BudgetNotAttempted BudgetResult = "not_attempted"
	BudgetConsumed     BudgetResult = "consumed"
	BudgetExhausted    BudgetResult = "exhausted"
	BudgetUnavailable  BudgetResult = "unavailable"
)

type Check struct {
	Required           bool         `json:"required"`
	LeaseID            string       `json:"lease_id,omitempty"`
	Issuer             string       `json:"issuer,omitempty"`
	IssuerKeyID        string       `json:"issuer_key_id,omitempty"`
	Result             CheckResult  `json:"result"`
	Reason             string       `json:"reason,omitempty"`
	ExpiresAt          time.Time    `json:"expires_at,omitempty"`
	GrantID            string       `json:"grant_id,omitempty"`
	SelectorDigest     string       `json:"selector_digest,omitempty"`
	SelectorDigestAlgo string       `json:"selector_digest_algo,omitempty"`
	BudgetResult       BudgetResult `json:"budget_result"`
	RemainingCount     *uint64      `json:"remaining_count,omitempty"`
}

type Issuer interface {
	Issue(ctx context.Context, payload Lease) (SignedLease, error)
}

type KeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

type Verifier interface {
	Verify(ctx context.Context, signed SignedLease, expected VerificationRequest) (VerifiedLease, error)
}

type IssuedRecord struct {
	LeaseID      string
	ExecutionID  string
	Issuer       string
	IssuerKeyID  string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	PolicyDigest string
	AuthorityDigest string
	Signed       SignedLease
	Lease        Lease
}

type ConsumeRequest struct {
	LeaseID    string
	GrantID    string
	ConsumedAt time.Time
	Approval   *approval.UseClaim
}

type ConsumeResult struct {
	RemainingCount uint64
}

type Store interface {
	PutIssued(ctx context.Context, record IssuedRecord) error
	LookupActiveByExecution(ctx context.Context, executionID string) (IssuedRecord, error)
	Consume(ctx context.Context, req ConsumeRequest) (ConsumeResult, error)
}
