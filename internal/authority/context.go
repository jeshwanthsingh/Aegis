package authority

import "aegis/internal/policy"

type ApprovalMode string

const (
	ApprovalModeNone               ApprovalMode = "none"
	ApprovalModeRequireHostConsent ApprovalMode = "require_host_consent"
)

type MountKind string

const (
	MountKindRootfs     MountKind = "rootfs"
	MountKindWorkspace  MountKind = "workspace"
	MountKindResolvConf MountKind = "resolv_conf"
)

type MountSpec struct {
	Name       string    `json:"name"`
	Kind       MountKind `json:"kind"`
	Target     string    `json:"target"`
	ReadOnly   bool      `json:"read_only"`
	Persistent bool      `json:"persistent,omitempty"`
}

type ResolvedHost struct {
	Host string   `json:"host"`
	IPv4 []string `json:"ipv4"`
}

type BootContext struct {
	RootfsPath      string                  `json:"-"`
	RootfsImage     string                  `json:"rootfs_image"`
	Mounts          []MountSpec             `json:"mounts"`
	NetworkMode     string                  `json:"network_mode"`
	EgressAllowlist policy.NetworkAllowlist `json:"egress_allowlist"`
	ResolvedHosts   []ResolvedHost          `json:"resolved_hosts,omitempty"`
}

type Context struct {
	ExecutionID          string       `json:"execution_id"`
	Boot                 BootContext  `json:"boot"`
	BrokerAllowedDomains []string     `json:"broker_allowed_domains,omitempty"`
	BrokerRepoLabels     []string     `json:"broker_repo_labels,omitempty"`
	BrokerActionTypes    []string     `json:"broker_action_types,omitempty"`
	ApprovalMode         ApprovalMode `json:"approval_mode"`
	PolicyDigest         string       `json:"policy_digest"`
	AuthorityDigest      string       `json:"authority_digest"`
}

type FreezeInput struct {
	ExecutionID          string
	AssetsDir            string
	RootfsPath           string
	WorkspaceRequested   bool
	Network              policy.NetworkPolicy
	BrokerAllowedDomains []string
	BrokerRepoLabels     []string
	BrokerActionTypes    []string
	ApprovalMode         ApprovalMode
	PolicyDigest         string
}

type MutationAttempt struct {
	Field            string `json:"field"`
	Expected         string `json:"expected"`
	Observed         string `json:"observed"`
	EnforcementPoint string `json:"enforcement_point"`
}
