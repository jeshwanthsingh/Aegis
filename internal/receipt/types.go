package receipt

import (
	"time"

	"aegis/internal/models"
	"aegis/internal/telemetry"
)

const (
	StatementType    = "https://in-toto.io/Statement/v1"
	PayloadType      = "application/vnd.in-toto+json"
	PredicateType    = "https://aegis.dev/ExecutionReceipt/v1"
	PredicateVersion = "v1"
	DefaultProofRoot = "/tmp/aegis/proofs"
)

type Input struct {
	ExecutionID     string
	WorkflowID      string
	Backend         models.RuntimeBackend
	TaskClass       string
	DeclaredPurpose string
	WorkspaceID     string
	ExecutionStatus string
	StartedAt       time.Time
	FinishedAt      time.Time
	IntentRaw       []byte
	Outcome         Outcome
	TelemetryEvents []telemetry.Event
	OutputArtifacts []Artifact
	Attributes      map[string]string
}

type Outcome struct {
	ExitCode           int
	Reason             string
	ContainmentVerdict string
	OutputTruncated    bool
}

type Artifact struct {
	Name      string            `json:"name"`
	Digest    map[string]string `json:"digest"`
	Path      string            `json:"path,omitempty"`
	MediaType string            `json:"media_type,omitempty"`
	Role      string            `json:"role,omitempty"`
}

type PointDecisionSummary struct {
	AllowCount         int `json:"allow_count"`
	DenyCount          int `json:"deny_count"`
	NotApplicableCount int `json:"not_applicable_count"`
}

type DivergenceSummary struct {
	Verdict          models.DivergenceVerdict `json:"verdict"`
	TriggeredRuleIDs []string                 `json:"triggered_rule_ids,omitempty"`
	RuleHitCount     int                      `json:"rule_hit_count"`
}

type TrustPosture struct {
	SigningMode          SigningMode `json:"signing_mode"`
	KeySource            KeySource   `json:"key_source"`
	Attestation          string      `json:"attestation"`
	VerificationMaterial string      `json:"verification_material"`
	Limitations          []string    `json:"limitations,omitempty"`
}

type ExecutionReceiptPredicate struct {
	Version            string                 `json:"version"`
	ExecutionID        string                 `json:"execution_id"`
	WorkflowID         string                 `json:"workflow_id,omitempty"`
	Backend            models.RuntimeBackend  `json:"backend"`
	TaskClass          string                 `json:"task_class,omitempty"`
	DeclaredPurpose    string                 `json:"declared_purpose,omitempty"`
	WorkspaceID        string                 `json:"workspace_id,omitempty"`
	ExecutionStatus    string                 `json:"execution_status,omitempty"`
	IntentDigest       string                 `json:"intent_digest,omitempty"`
	IntentDigestAlgo   string                 `json:"intent_digest_algo,omitempty"`
	EvidenceDigest     string                 `json:"evidence_digest"`
	EvidenceDigestAlgo string                 `json:"evidence_digest_algo"`
	RuntimeEventCount  int                    `json:"runtime_event_count"`
	PointDecisions     PointDecisionSummary   `json:"point_decisions"`
	Divergence         DivergenceSummary      `json:"divergence"`
	Outcome            Outcome                `json:"outcome"`
	Trust              TrustPosture           `json:"trust"`
	Limitations        []string               `json:"limitations,omitempty"`
	StartedAt          time.Time              `json:"started_at"`
	FinishedAt         time.Time              `json:"finished_at"`
	SignerKeyID        string                 `json:"signer_key_id"`
	BrokerSummary      *BrokerSummary         `json:"broker_summary,omitempty"`
	GovernedActions    *GovernedActionSummary `json:"governed_actions,omitempty"`
	Metadata           map[string]string      `json:"metadata,omitempty"`
}

type BrokerSummary struct {
	RequestCount   int      `json:"request_count"`
	AllowedCount   int      `json:"allowed_count"`
	DeniedCount    int      `json:"denied_count"`
	DomainsAllowed []string `json:"domains_allowed,omitempty"`
	DomainsDenied  []string `json:"domains_denied,omitempty"`
	BindingsUsed   []string `json:"bindings_used,omitempty"`
}

type GovernedActionSummary struct {
	Count   int                    `json:"count"`
	Actions []GovernedActionRecord `json:"actions,omitempty"`
}

type GovernedActionRecord struct {
	ActionType          string            `json:"action_type"`
	Target              string            `json:"target"`
	Resource            string            `json:"resource,omitempty"`
	Method              string            `json:"method,omitempty"`
	Decision            string            `json:"decision"`
	Reason              string            `json:"reason,omitempty"`
	RuleID              string            `json:"rule_id,omitempty"`
	PolicyDigest        string            `json:"policy_digest,omitempty"`
	Brokered            bool              `json:"brokered"`
	BrokeredCredentials bool              `json:"brokered_credentials"`
	BindingName         string            `json:"binding_name,omitempty"`
	ResponseDigest      string            `json:"response_digest,omitempty"`
	ResponseDigestAlgo  string            `json:"response_digest_algo,omitempty"`
	DenialMarker        string            `json:"denial_marker,omitempty"`
	AuditPayload        map[string]string `json:"audit_payload,omitempty"`
}

type StatementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string                    `json:"_type"`
	Subject       []StatementSubject        `json:"subject"`
	PredicateType string                    `json:"predicateType"`
	Predicate     ExecutionReceiptPredicate `json:"predicate"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type SignedReceipt struct {
	Envelope  Envelope  `json:"envelope"`
	Statement Statement `json:"statement"`
}

type BundlePaths struct {
	ProofDir          string            `json:"proof_dir"`
	ReceiptPath       string            `json:"receipt_path"`
	PublicKeyPath     string            `json:"receipt_public_key_path"`
	SummaryPath       string            `json:"receipt_summary_path"`
	ArtifactPaths     map[string]string `json:"artifact_paths,omitempty"`
	ArtifactCount     int               `json:"artifact_count"`
	DivergenceVerdict string            `json:"divergence_verdict,omitempty"`
}
