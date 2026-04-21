package approval

import (
	"context"
	"crypto/ed25519"
	"time"

	"aegis/internal/dsse"
)

const (
	TicketVersion       = "v1"
	TicketPredicateType = "https://aegis.dev/ApprovalTicket/v1"
	EnvPublicKeysJSON   = "AEGIS_APPROVAL_PUBLIC_KEYS_JSON"
	ResourceDigestAlgo  = "sha256"
)

type ResourceKind string

const (
	ResourceKindHTTPRequestV1        ResourceKind = "http_request_v1"
	ResourceKindHostRepoApplyPatchV1 ResourceKind = "host_repo_apply_patch_v1"
)

type Ticket struct {
	Version      string    `json:"version"`
	TicketID     string    `json:"ticket_id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Nonce        string    `json:"nonce"`
	ExecutionID  string    `json:"execution_id"`
	PolicyDigest string    `json:"policy_digest"`
	ActionType   string    `json:"action_type"`
	Resource     Resource  `json:"resource"`
}

type Resource struct {
	Kind               ResourceKind                `json:"kind"`
	HTTP               *HTTPRequestResource        `json:"http,omitempty"`
	HostRepoApplyPatch *HostRepoApplyPatchResource `json:"host_repo_apply_patch,omitempty"`
}

type HTTPRequestResource struct {
	Method            string `json:"method"`
	URL               string `json:"url"`
	HeadersDigest     string `json:"headers_digest"`
	HeadersDigestAlgo string `json:"headers_digest_algo"`
	BodyDigest        string `json:"body_digest"`
	BodyDigestAlgo    string `json:"body_digest_algo"`
}

type HostRepoApplyPatchResource struct {
	RepoLabel       string   `json:"repo_label"`
	TargetScope     []string `json:"target_scope,omitempty"`
	AffectedPaths   []string `json:"affected_paths"`
	PatchDigest     string   `json:"patch_digest"`
	PatchDigestAlgo string   `json:"patch_digest_algo"`
	BaseRevision    string   `json:"base_revision"`
}

type Statement struct {
	Type          string                  `json:"_type"`
	Subject       []dsse.StatementSubject `json:"subject"`
	PredicateType string                  `json:"predicateType"`
	Predicate     Ticket                  `json:"predicate"`
}

type SignedTicket struct {
	Envelope  dsse.Envelope `json:"envelope"`
	Statement Statement     `json:"statement"`
}

type HTTPRequestInput struct {
	Method  string
	URL     string
	Headers map[string][]string
	Body    []byte
}

type CanonicalResource struct {
	Resource           Resource
	SanitizedHeaders   map[string][]string
	Body               []byte
	ResourceDigest     string
	ResourceDigestAlgo string
}

type VerificationRequest struct {
	ExecutionID  string
	PolicyDigest string
	ActionType   string
	Resource     Resource
	Now          time.Time
}

type VerifiedTicket struct {
	Ticket             Ticket
	IssuerKeyID        string
	ResourceDigest     string
	ResourceDigestAlgo string
}

type UseClaim struct {
	TicketID           string
	Nonce              string
	ExecutionID        string
	PolicyDigest       string
	ActionType         string
	ResourceDigest     string
	ResourceDigestAlgo string
	ConsumedAt         time.Time
}

type VerificationResult string

const (
	VerificationVerified           VerificationResult = "verified"
	VerificationMissing            VerificationResult = "missing"
	VerificationExpired            VerificationResult = "expired"
	VerificationReused             VerificationResult = "reused"
	VerificationExecutionMismatch  VerificationResult = "execution_id_mismatch"
	VerificationPolicyMismatch     VerificationResult = "policy_digest_mismatch"
	VerificationActionTypeMismatch VerificationResult = "action_type_mismatch"
	VerificationResourceMismatch   VerificationResult = "resource_mismatch"
	VerificationMalformed          VerificationResult = "malformed"
	VerificationSignatureInvalid   VerificationResult = "signature_invalid"
	VerificationUnavailable        VerificationResult = "unavailable"
)

type Check struct {
	Required           bool               `json:"required"`
	TicketID           string             `json:"ticket_id,omitempty"`
	IssuerKeyID        string             `json:"issuer_key_id,omitempty"`
	Result             VerificationResult `json:"result"`
	Reason             string             `json:"reason,omitempty"`
	ExpiresAt          time.Time          `json:"expires_at,omitempty"`
	ResourceDigest     string             `json:"resource_digest,omitempty"`
	ResourceDigestAlgo string             `json:"resource_digest_algo,omitempty"`
	Consumed           bool               `json:"consumed,omitempty"`
}

type Issuer interface {
	Issue(ctx context.Context, payload Ticket) (SignedTicket, error)
}

type KeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error)
}

type UseStore interface {
	ConsumeApprovalTicket(ctx context.Context, claim UseClaim) error
}

type Verifier interface {
	Verify(ctx context.Context, ticket SignedTicket, expected VerificationRequest) (VerifiedTicket, error)
}
