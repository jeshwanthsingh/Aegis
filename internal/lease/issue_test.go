package lease

import (
	"slices"
	"testing"
	"time"

	"aegis/internal/authority"
)

func testFrozenAuthority() authority.Context {
	return authority.Context{
		ExecutionID:     "exec-lease-test",
		PolicyDigest:    "policy-digest",
		AuthorityDigest: "authority-digest",
		Boot: authority.BootContext{
			RootfsImage: "aegis-rootfs:test",
		},
	}
}

func TestBuildExecutionLeaseIssuesDomainOnlyHTTPGrants(t *testing.T) {
	frozen := testFrozenAuthority()
	frozen.BrokerAllowedDomains = []string{"API.EXAMPLE.COM", "api.example.com"}
	frozen.BrokerActionTypes = []string{string(ActionKindHTTPRequest)}
	frozen.ApprovalMode = authority.ApprovalModeRequireHostConsent

	issuedAt := time.Unix(100, 0).UTC()
	expiresAt := time.Unix(200, 0).UTC()
	leaseValue, err := BuildExecutionLease(IssueInput{
		Frozen:    frozen,
		Issuer:    "test-issuer",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Budgets: BudgetDefaults{
			HTTPCount: 7,
		},
	})
	if err != nil {
		t.Fatalf("BuildExecutionLease: %v", err)
	}
	if len(leaseValue.Grants) != 1 {
		t.Fatalf("grant count = %d, want 1", len(leaseValue.Grants))
	}
	grant := leaseValue.Grants[0]
	if grant.ActionKind != ActionKindHTTPRequest {
		t.Fatalf("action kind = %q, want %q", grant.ActionKind, ActionKindHTTPRequest)
	}
	if grant.Selector.Kind != SelectorKindHTTPRequestV1 || grant.Selector.HTTP == nil {
		t.Fatalf("selector = %+v", grant.Selector)
	}
	if got, want := grant.Selector.HTTP.Domain, "api.example.com"; got != want {
		t.Fatalf("domain = %q, want %q", got, want)
	}
	if len(grant.Selector.HTTP.Methods) != 0 {
		t.Fatalf("methods should be omitted when not frozen/enforced: %v", grant.Selector.HTTP.Methods)
	}
	if len(grant.Selector.HTTP.PathPrefixes) != 0 {
		t.Fatalf("path prefixes should be omitted when not frozen/enforced: %v", grant.Selector.HTTP.PathPrefixes)
	}
	if got, want := grant.Budget.LimitCount, uint64(7); got != want {
		t.Fatalf("budget limit = %d, want %d", got, want)
	}
	if leaseValue.TrustLimits == nil || !slices.Equal(leaseValue.TrustLimits.ApprovalRequiredActionKinds, []ActionKind{ActionKindHTTPRequest}) {
		t.Fatalf("trust limits = %+v", leaseValue.TrustLimits)
	}
}

func TestBuildExecutionLeaseIssuesRepoLabelOnlyHostPatchGrant(t *testing.T) {
	frozen := testFrozenAuthority()
	frozen.BrokerActionTypes = []string{string(ActionKindHostRepoApplyPatch)}
	frozen.BrokerRepoLabels = []string{"DEMO", "demo"}

	leaseValue, err := BuildExecutionLease(IssueInput{
		Frozen:    frozen,
		Issuer:    "test-issuer",
		IssuedAt:  time.Unix(100, 0).UTC(),
		ExpiresAt: time.Unix(200, 0).UTC(),
		Budgets: BudgetDefaults{
			HostPatchCount: 3,
		},
	})
	if err != nil {
		t.Fatalf("BuildExecutionLease: %v", err)
	}
	if len(leaseValue.Grants) != 1 {
		t.Fatalf("grant count = %d, want 1", len(leaseValue.Grants))
	}
	grant := leaseValue.Grants[0]
	if grant.ActionKind != ActionKindHostRepoApplyPatch {
		t.Fatalf("action kind = %q, want %q", grant.ActionKind, ActionKindHostRepoApplyPatch)
	}
	if grant.Selector.Kind != SelectorKindHostRepoApplyPatchV1 || grant.Selector.HostRepoApplyPatch == nil {
		t.Fatalf("selector = %+v", grant.Selector)
	}
	if got, want := grant.Selector.HostRepoApplyPatch.RepoLabel, "demo"; got != want {
		t.Fatalf("repo label = %q, want %q", got, want)
	}
	if len(grant.Selector.HostRepoApplyPatch.TargetScope) != 0 {
		t.Fatalf("target scope should be omitted when not frozen/enforced: %v", grant.Selector.HostRepoApplyPatch.TargetScope)
	}
	if got, want := grant.Budget.LimitCount, uint64(3); got != want {
		t.Fatalf("budget limit = %d, want %d", got, want)
	}
	if leaseValue.TrustLimits == nil || !slices.Equal(leaseValue.TrustLimits.ApprovalRequiredActionKinds, []ActionKind{ActionKindHostRepoApplyPatch}) {
		t.Fatalf("trust limits = %+v", leaseValue.TrustLimits)
	}
}
