package lease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
)

func testLeasePrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func signedHTTPLeaseForTest(t *testing.T, privateKey ed25519.PrivateKey) SignedLease {
	t.Helper()
	frozen := testFrozenAuthority()
	frozen.BrokerAllowedDomains = []string{"api.example.com"}
	frozen.BrokerActionTypes = []string{string(ActionKindHTTPRequest)}
	payload, err := BuildExecutionLease(IssueInput{
		Frozen:    frozen,
		Issuer:    "test-issuer",
		IssuedAt:  time.Unix(100, 0).UTC(),
		ExpiresAt: time.Unix(200, 0).UTC(),
		Budgets: BudgetDefaults{
			HTTPCount: 2,
		},
	})
	if err != nil {
		t.Fatalf("BuildExecutionLease: %v", err)
	}
	signed, err := SignLease(payload, privateKey)
	if err != nil {
		t.Fatalf("SignLease: %v", err)
	}
	return signed
}

func signedHostPatchLeaseForTest(t *testing.T, privateKey ed25519.PrivateKey) SignedLease {
	t.Helper()
	frozen := testFrozenAuthority()
	frozen.BrokerActionTypes = []string{string(ActionKindHostRepoApplyPatch)}
	frozen.BrokerRepoLabels = []string{"demo"}
	payload, err := BuildExecutionLease(IssueInput{
		Frozen:    frozen,
		Issuer:    "test-issuer",
		IssuedAt:  time.Unix(100, 0).UTC(),
		ExpiresAt: time.Unix(200, 0).UTC(),
		Budgets: BudgetDefaults{
			HostPatchCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("BuildExecutionLease: %v", err)
	}
	signed, err := SignLease(payload, privateKey)
	if err != nil {
		t.Fatalf("SignLease: %v", err)
	}
	return signed
}

func testLeaseVerifier(privateKey ed25519.PrivateKey) *LeaseVerifier {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return NewVerifier(NewStaticKeyResolver(map[string]ed25519.PublicKey{
		dsse.KeyIDFromPublicKey(publicKey): publicKey,
	}))
}

func testHTTPLeaseResource(t *testing.T, rawURL string) approval.Resource {
	t.Helper()
	resource, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method: "GET",
		URL:    rawURL,
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	return resource.Resource
}

func testHostPatchLeaseResource(t *testing.T, repoLabel string) approval.Resource {
	t.Helper()
	resource, err := approval.CanonicalizeResource(approval.Resource{
		Kind: approval.ResourceKindHostRepoApplyPatchV1,
		HostRepoApplyPatch: &approval.HostRepoApplyPatchResource{
			RepoLabel:       repoLabel,
			AffectedPaths:   []string{"README.md"},
			PatchDigest:     strings.Repeat("a", 64),
			PatchDigestAlgo: approval.ResourceDigestAlgo,
			BaseRevision:    strings.Repeat("b", 40),
		},
	})
	if err != nil {
		t.Fatalf("CanonicalizeResource: %v", err)
	}
	return resource
}

func TestVerifierAcceptsMatchingLease(t *testing.T) {
	privateKey := testLeasePrivateKey(1)
	verifier := testLeaseVerifier(privateKey)
	signed := signedHTTPLeaseForTest(t, privateKey)

	verified, err := verifier.Verify(context.Background(), signed, VerificationRequest{
		ExecutionID:     "exec-lease-test",
		PolicyDigest:    "policy-digest",
		AuthorityDigest: "authority-digest",
		ActionKind:      ActionKindHTTPRequest,
		Resource:        testHTTPLeaseResource(t, "https://api.example.com/v1/items"),
		Now:             time.Unix(150, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Grant.ActionKind != ActionKindHTTPRequest {
		t.Fatalf("verified grant = %+v", verified.Grant)
	}
	if verified.SelectorDigest == "" || verified.SelectorDigestAlgo != approval.ResourceDigestAlgo {
		t.Fatalf("selector digest = %q algo=%q", verified.SelectorDigest, verified.SelectorDigestAlgo)
	}
}

func TestVerifierRejectsExpiredExecutionPolicyAndAuthorityMismatches(t *testing.T) {
	privateKey := testLeasePrivateKey(2)
	verifier := testLeaseVerifier(privateKey)
	signed := signedHTTPLeaseForTest(t, privateKey)
	resource := testHTTPLeaseResource(t, "https://api.example.com/v1/items")

	tests := []struct {
		name       string
		req        VerificationRequest
		wantResult CheckResult
		wantReason string
	}{
		{
			name: "expired",
			req: VerificationRequest{
				ExecutionID:     "exec-lease-test",
				PolicyDigest:    "policy-digest",
				AuthorityDigest: "authority-digest",
				ActionKind:      ActionKindHTTPRequest,
				Resource:        resource,
				Now:             time.Unix(250, 0).UTC(),
			},
			wantResult: CheckExpired,
			wantReason: "broker.lease_expired",
		},
		{
			name: "wrong_execution",
			req: VerificationRequest{
				ExecutionID:     "other-exec",
				PolicyDigest:    "policy-digest",
				AuthorityDigest: "authority-digest",
				ActionKind:      ActionKindHTTPRequest,
				Resource:        resource,
				Now:             time.Unix(150, 0).UTC(),
			},
			wantResult: CheckExecutionMismatch,
			wantReason: "broker.lease_execution_mismatch",
		},
		{
			name: "wrong_policy",
			req: VerificationRequest{
				ExecutionID:     "exec-lease-test",
				PolicyDigest:    "other-policy",
				AuthorityDigest: "authority-digest",
				ActionKind:      ActionKindHTTPRequest,
				Resource:        resource,
				Now:             time.Unix(150, 0).UTC(),
			},
			wantResult: CheckPolicyMismatch,
			wantReason: "broker.lease_policy_mismatch",
		},
		{
			name: "wrong_authority",
			req: VerificationRequest{
				ExecutionID:     "exec-lease-test",
				PolicyDigest:    "policy-digest",
				AuthorityDigest: "other-authority",
				ActionKind:      ActionKindHTTPRequest,
				Resource:        resource,
				Now:             time.Unix(150, 0).UTC(),
			},
			wantResult: CheckAuthorityMismatch,
			wantReason: "broker.lease_authority_mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), signed, tc.req)
			var verifyErr *VerificationError
			if err == nil || !errors.As(err, &verifyErr) {
				t.Fatalf("expected verification error, got %v", err)
			}
			if verifyErr.Result != tc.wantResult || verifyErr.Reason != tc.wantReason {
				t.Fatalf("verification error = %+v, want result=%q reason=%q", verifyErr, tc.wantResult, tc.wantReason)
			}
		})
	}
}

func TestVerifierRejectsSelectorMismatch(t *testing.T) {
	privateKey := testLeasePrivateKey(3)
	verifier := testLeaseVerifier(privateKey)

	httpSigned := signedHTTPLeaseForTest(t, privateKey)
	_, err := verifier.Verify(context.Background(), httpSigned, VerificationRequest{
		ExecutionID:     "exec-lease-test",
		PolicyDigest:    "policy-digest",
		AuthorityDigest: "authority-digest",
		ActionKind:      ActionKindHTTPRequest,
		Resource:        testHTTPLeaseResource(t, "https://other.example.com/v1/items"),
		Now:             time.Unix(150, 0).UTC(),
	})
	var verifyErr *VerificationError
	if err == nil || !errors.As(err, &verifyErr) || verifyErr.Result != CheckResourceMismatch {
		t.Fatalf("expected http resource mismatch, got %v", err)
	}

	hostSigned := signedHostPatchLeaseForTest(t, privateKey)
	_, err = verifier.Verify(context.Background(), hostSigned, VerificationRequest{
		ExecutionID:     "exec-lease-test",
		PolicyDigest:    "policy-digest",
		AuthorityDigest: "authority-digest",
		ActionKind:      ActionKindHostRepoApplyPatch,
		Resource:        testHostPatchLeaseResource(t, "other"),
		Now:             time.Unix(150, 0).UTC(),
	})
	if err == nil || !errors.As(err, &verifyErr) || verifyErr.Result != CheckResourceMismatch {
		t.Fatalf("expected host patch resource mismatch, got %v", err)
	}
}
