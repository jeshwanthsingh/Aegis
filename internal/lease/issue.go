package lease

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"aegis/internal/authority"
)

type IssueInput struct {
	Frozen    authority.Context
	Issuer    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Budgets   BudgetDefaults
}

func BuildExecutionLease(input IssueInput) (Lease, error) {
	frozen := input.Frozen
	if strings.TrimSpace(frozen.ExecutionID) == "" {
		return Lease{}, fmt.Errorf("execution_id is required")
	}
	if strings.TrimSpace(frozen.PolicyDigest) == "" {
		return Lease{}, fmt.Errorf("policy_digest is required")
	}
	if strings.TrimSpace(frozen.AuthorityDigest) == "" {
		return Lease{}, fmt.Errorf("authority_digest is required")
	}
	issuedAt := input.IssuedAt.UTC()
	if issuedAt.IsZero() {
		issuedAt = time.Now().UTC()
	}
	expiresAt := input.ExpiresAt.UTC()
	if expiresAt.IsZero() || !expiresAt.After(issuedAt) {
		return Lease{}, fmt.Errorf("expires_at must be after issued_at")
	}
	budgets := normalizeBudgetDefaults(input.Budgets)
	issuer := strings.TrimSpace(input.Issuer)
	if issuer == "" {
		issuer = DefaultIssuerName
	}
	lease := Lease{
		Version:         LeaseVersion,
		LeaseID:         newLeaseID(frozen.ExecutionID, issuedAt, frozen.AuthorityDigest),
		Issuer:          issuer,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		ExecutionID:     frozen.ExecutionID,
		PolicyDigest:    frozen.PolicyDigest,
		AuthorityDigest: frozen.AuthorityDigest,
		Workload: WorkloadIdentity{
			Kind:        "aegis_execution_boot_v1",
			BootDigest:  authority.BootDigest(frozen.Boot),
			RootfsImage: strings.TrimSpace(frozen.Boot.RootfsImage),
		},
	}
	grants := make([]Grant, 0)
	for _, domain := range sortedUniqueStrings(frozen.BrokerAllowedDomains) {
		if !containsString(frozen.BrokerActionTypes, string(ActionKindHTTPRequest)) {
			break
		}
		selector := ResourceSelector{
			Kind: SelectorKindHTTPRequestV1,
			HTTP: &HTTPRequestSelector{Domain: domain},
		}
		grant, err := newGrant(ActionKindHTTPRequest, selector, budgets.HTTPCount)
		if err != nil {
			return Lease{}, err
		}
		grants = append(grants, grant)
	}
	if containsString(frozen.BrokerActionTypes, string(ActionKindHostRepoApplyPatch)) {
		for _, repoLabel := range sortedUniqueStrings(frozen.BrokerRepoLabels) {
			selector := ResourceSelector{
				Kind: SelectorKindHostRepoApplyPatchV1,
				HostRepoApplyPatch: &HostRepoApplyPatchSelector{
					RepoLabel: repoLabel,
				},
			}
			grant, err := newGrant(ActionKindHostRepoApplyPatch, selector, budgets.HostPatchCount)
			if err != nil {
				return Lease{}, err
			}
			grants = append(grants, grant)
		}
	}
	if len(grants) == 0 {
		return Lease{}, fmt.Errorf("lease requires at least one grant")
	}
	lease.Grants = grants
	if limits := buildTrustLimitations(frozen, grants); limits != nil {
		lease.TrustLimits = limits
	}
	return lease, nil
}

func BudgetDefaultsFromEnv() (BudgetDefaults, error) {
	httpBudget, err := parseUintEnv(EnvDefaultHTTPCountBudget, DefaultHTTPCountBudget)
	if err != nil {
		return BudgetDefaults{}, err
	}
	hostPatchBudget, err := parseUintEnv(EnvDefaultHostPatchCountBudget, DefaultHostPatchCountBudget)
	if err != nil {
		return BudgetDefaults{}, err
	}
	return BudgetDefaults{
		HTTPCount:      httpBudget,
		HostPatchCount: hostPatchBudget,
	}, nil
}

func IssuerNameFromEnv() string {
	if value := strings.TrimSpace(os.Getenv(EnvIssuer)); value != "" {
		return value
	}
	return DefaultIssuerName
}

func normalizeBudgetDefaults(input BudgetDefaults) BudgetDefaults {
	result := input
	if result.HTTPCount == 0 {
		result.HTTPCount = DefaultHTTPCountBudget
	}
	if result.HostPatchCount == 0 {
		result.HostPatchCount = DefaultHostPatchCountBudget
	}
	return result
}

func newGrant(actionKind ActionKind, selector ResourceSelector, limitCount uint64) (Grant, error) {
	canonical, err := CanonicalizeSelector(selector)
	if err != nil {
		return Grant{}, fmt.Errorf("canonicalize %s selector: %w", actionKind, err)
	}
	digest, _, err := DigestSelector(canonical)
	if err != nil {
		return Grant{}, fmt.Errorf("digest %s selector: %w", actionKind, err)
	}
	return Grant{
		GrantID:    fmt.Sprintf("grant_%s_%s", actionKind, digest[:16]),
		ActionKind: actionKind,
		Selector:   canonical,
		Budget: Budget{
			Kind:       BudgetKindCount,
			LimitCount: limitCount,
		},
	}, nil
}

func buildTrustLimitations(frozen authority.Context, grants []Grant) *TrustLimitations {
	required := make([]ActionKind, 0, 2)
	if containsGrant(grants, ActionKindHostRepoApplyPatch) {
		required = append(required, ActionKindHostRepoApplyPatch)
	}
	if frozen.ApprovalMode == authority.ApprovalModeRequireHostConsent && containsGrant(grants, ActionKindHTTPRequest) {
		required = append(required, ActionKindHTTPRequest)
	}
	if len(required) == 0 {
		return nil
	}
	sort.Slice(required, func(i, j int) bool { return required[i] < required[j] })
	return &TrustLimitations{ApprovalRequiredActionKinds: required}
}

func containsGrant(grants []Grant, actionKind ActionKind) bool {
	for _, grant := range grants {
		if grant.ActionKind == actionKind {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(strings.ToLower(raw))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func parseUintEnv(name string, fallback uint64) (uint64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return value, nil
}

func newLeaseID(executionID string, issuedAt time.Time, authorityDigest string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(executionID),
		issuedAt.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(authorityDigest),
	}, "|")))
	return "lease_" + hex.EncodeToString(sum[:8])
}
