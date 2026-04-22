package receipt

import (
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/models"
	"aegis/internal/telemetry"
)

const (
	StatementType    = dsse.StatementType
	PayloadType      = dsse.PayloadType
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
	Policy          *PolicyEnvelope
	Authority       *AuthorityEnvelope
	Outcome         Outcome
	Runtime         *RuntimeEnvelope
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

type ResultClass string

const (
	ResultClassCompleted  ResultClass = "completed"
	ResultClassDenied     ResultClass = "denied"
	ResultClassAbnormal   ResultClass = "abnormal"
	ResultClassReconciled ResultClass = "reconciled"
)

type DenialClass string

const (
	DenialClassGovernedAction DenialClass = "governed_action"
	DenialClassPolicy         DenialClass = "policy"
)

type DenialSummary struct {
	Class  DenialClass `json:"class"`
	RuleID string      `json:"rule_id,omitempty"`
	Marker string      `json:"marker,omitempty"`
}

type SemanticsMode string

const (
	SemanticsModeExplicitV1    SemanticsMode = "explicit_v1"
	SemanticsModeExplicitV2    SemanticsMode = "explicit_v2"
	SemanticsModeLegacyDerived SemanticsMode = "legacy_derived"
)

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

type RuntimeEnvelope struct {
	Profile          string                            `json:"profile,omitempty"`
	VCPUCount        int                               `json:"vcpu_count,omitempty"`
	MemoryMB         int                               `json:"memory_mb,omitempty"`
	Cgroup           *RuntimeCgroupEnvelope            `json:"cgroup,omitempty"`
	Network          *RuntimeNetworkEnvelope           `json:"network,omitempty"`
	Broker           *RuntimeBrokerEnvelope            `json:"broker,omitempty"`
	Policy           *escalation.RuntimePolicyEnvelope `json:"policy,omitempty"`
	AppliedOverrides []string                          `json:"applied_overrides,omitempty"`
}

type RuntimeCgroupEnvelope struct {
	MemoryMaxMB  int    `json:"memory_max_mb,omitempty"`
	MemoryHighMB int    `json:"memory_high_mb,omitempty"`
	PidsMax      int    `json:"pids_max,omitempty"`
	CPUMax       string `json:"cpu_max,omitempty"`
	SwapMax      string `json:"swap_max,omitempty"`
}

type RuntimeNetworkEnvelope struct {
	Enabled       bool                      `json:"enabled"`
	Mode          string                    `json:"mode"`
	Presets       []string                  `json:"presets"`
	Allowlist     *NetworkAllowlistEnvelope `json:"allowlist,omitempty"`
	BlockedEgress *BlockedEgressSummary     `json:"blocked_egress,omitempty"`
}

type RuntimeBrokerEnvelope struct {
	Enabled bool `json:"enabled"`
}

type PolicyIntentSource string

const (
	PolicyIntentSourceContract             PolicyIntentSource = "intent_contract"
	PolicyIntentSourceCompiledCapabilities PolicyIntentSource = "compiled_capabilities"
)

type PolicyEnvelope struct {
	Baseline BaselinePolicy      `json:"baseline"`
	Intent   *IntentPolicyDigest `json:"intent,omitempty"`
}

type BaselinePolicy struct {
	Language      string                 `json:"language"`
	CodeSizeBytes int                    `json:"code_size_bytes"`
	MaxCodeBytes  int                    `json:"max_code_bytes"`
	TimeoutMs     int                    `json:"timeout_ms"`
	MaxTimeoutMs  int                    `json:"max_timeout_ms"`
	Profile       string                 `json:"profile,omitempty"`
	Network       *BaselineNetworkPolicy `json:"network,omitempty"`
}

type BaselineNetworkPolicy struct {
	Mode      string                    `json:"mode"`
	Presets   []string                  `json:"presets"`
	Allowlist *NetworkAllowlistEnvelope `json:"allowlist,omitempty"`
}

type NetworkAllowlistEnvelope struct {
	FQDNs []string `json:"fqdns"`
	CIDRs []string `json:"cidrs"`
}

type BlockedEgressSummary struct {
	TotalCount        int                  `json:"total_count"`
	UniqueTargetCount int                  `json:"unique_target_count"`
	Sample            []BlockedEgressEntry `json:"sample"`
	SampleTruncated   bool                 `json:"sample_truncated"`
}

type BlockedEgressEntry struct {
	Target      string    `json:"target"`
	Kind        string    `json:"kind"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	Count       int       `json:"count"`
}

type IntentPolicyDigest struct {
	Digest string             `json:"digest"`
	Source PolicyIntentSource `json:"source,omitempty"`
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
	SemanticsMode      SemanticsMode          `json:"semantics_mode,omitempty"`
	ResultClass        ResultClass            `json:"result_class"`
	Denial             *DenialSummary         `json:"denial,omitempty"`
	PolicyDigest       string                 `json:"policy_digest,omitempty"`
	IntentDigest       string                 `json:"intent_digest,omitempty"`
	IntentDigestAlgo   string                 `json:"intent_digest_algo,omitempty"`
	Policy             *PolicyEnvelope        `json:"policy,omitempty"`
	Authority          *AuthorityEnvelope     `json:"authority,omitempty"`
	EvidenceDigest     string                 `json:"evidence_digest"`
	EvidenceDigestAlgo string                 `json:"evidence_digest_algo"`
	RuntimeEventCount  int                    `json:"runtime_event_count"`
	PointDecisions     PointDecisionSummary   `json:"point_decisions"`
	Divergence         DivergenceSummary      `json:"divergence"`
	Outcome            Outcome                `json:"outcome"`
	Runtime            *RuntimeEnvelope       `json:"runtime,omitempty"`
	Trust              TrustPosture           `json:"trust"`
	Limitations        []string               `json:"limitations,omitempty"`
	StartedAt          time.Time              `json:"started_at"`
	FinishedAt         time.Time              `json:"finished_at"`
	SignerKeyID        string                 `json:"signer_key_id"`
	BrokerSummary      *BrokerSummary         `json:"broker_summary,omitempty"`
	GovernedActions    *GovernedActionSummary `json:"governed_actions,omitempty"`
	Metadata           map[string]string      `json:"metadata,omitempty"`
}

type AuthorityEnvelope struct {
	Digest               string                          `json:"digest"`
	RootfsImage          string                          `json:"rootfs_image"`
	Mounts               []AuthorityMountEnvelope        `json:"mounts"`
	NetworkMode          string                          `json:"network_mode"`
	EgressAllowlist      *NetworkAllowlistEnvelope       `json:"egress_allowlist,omitempty"`
	ResolvedHosts        []AuthorityResolvedHostEnvelope `json:"resolved_hosts,omitempty"`
	BrokerAllowedDomains []string                        `json:"broker_allowed_domains,omitempty"`
	BrokerRepoLabels     []string                        `json:"broker_repo_labels,omitempty"`
	BrokerActionTypes    []string                        `json:"broker_action_types,omitempty"`
	ApprovalMode         string                          `json:"approval_mode"`
	MutationAttempt      *AuthorityMutationEnvelope      `json:"mutation_attempt,omitempty"`
}

type AuthorityMountEnvelope struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	ReadOnly   bool   `json:"read_only"`
	Persistent bool   `json:"persistent,omitempty"`
}

type AuthorityResolvedHostEnvelope struct {
	Host string   `json:"host"`
	IPv4 []string `json:"ipv4"`
}

type AuthorityMutationEnvelope struct {
	Field            string `json:"field"`
	Expected         string `json:"expected"`
	Observed         string `json:"observed"`
	EnforcementPoint string `json:"enforcement_point"`
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
	Count      int                             `json:"count"`
	Actions    []GovernedActionRecord          `json:"actions,omitempty"`
	Normalized []NormalizedGovernedActionEntry `json:"normalized,omitempty"`
}

type GovernedActionRecord struct {
	ActionType          string               `json:"action_type"`
	Target              string               `json:"target"`
	Resource            string               `json:"resource,omitempty"`
	Method              string               `json:"method,omitempty"`
	CapabilityPath      string               `json:"capability_path,omitempty"`
	Decision            string               `json:"decision"`
	Outcome             string               `json:"outcome,omitempty"`
	Used                bool                 `json:"used"`
	Reason              string               `json:"reason,omitempty"`
	RuleID              string               `json:"rule_id,omitempty"`
	PolicyDigest        string               `json:"policy_digest,omitempty"`
	Brokered            bool                 `json:"brokered"`
	BrokeredCredentials bool                 `json:"brokered_credentials"`
	BindingName         string               `json:"binding_name,omitempty"`
	ResponseDigest      string               `json:"response_digest,omitempty"`
	ResponseDigestAlgo  string               `json:"response_digest_algo,omitempty"`
	DenialMarker        string               `json:"denial_marker,omitempty"`
	AuditPayload        map[string]string    `json:"audit_payload,omitempty"`
	Error               string               `json:"error,omitempty"`
	Approval            *approval.Check      `json:"approval,omitempty"`
	Lease               *lease.Check         `json:"lease,omitempty"`
	Escalation          *escalation.Evidence `json:"escalation,omitempty"`
	HostAction          *hostaction.Evidence `json:"host_action,omitempty"`
}

type NormalizedGovernedActionEntry struct {
	Count               int               `json:"count"`
	ActionType          string            `json:"action_type"`
	Target              string            `json:"target"`
	Resource            string            `json:"resource,omitempty"`
	Method              string            `json:"method,omitempty"`
	CapabilityPath      string            `json:"capability_path,omitempty"`
	Decision            string            `json:"decision"`
	Outcome             string            `json:"outcome,omitempty"`
	Used                bool              `json:"used"`
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
	Error               string            `json:"error,omitempty"`
}

type Statement struct {
	Type          string                    `json:"_type"`
	Subject       []StatementSubject        `json:"subject"`
	PredicateType string                    `json:"predicateType"`
	Predicate     ExecutionReceiptPredicate `json:"predicate"`
}

type SignedReceipt struct {
	Envelope  Envelope  `json:"envelope"`
	Statement Statement `json:"statement"`
}

type StatementSubject = dsse.StatementSubject

type Signature = dsse.Signature

type Envelope = dsse.Envelope

type BundlePaths struct {
	ProofDir          string            `json:"proof_dir"`
	ReceiptPath       string            `json:"receipt_path"`
	PublicKeyPath     string            `json:"receipt_public_key_path"`
	SummaryPath       string            `json:"receipt_summary_path"`
	ArtifactPaths     map[string]string `json:"artifact_paths,omitempty"`
	ArtifactCount     int               `json:"artifact_count"`
	DivergenceVerdict string            `json:"divergence_verdict,omitempty"`
}
