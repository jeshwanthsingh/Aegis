package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

type stubPrepared struct {
	response hostaction.Response
	err      error
}

func (p *stubPrepared) Apply(context.Context) (hostaction.Response, error) {
	if p.err != nil {
		return hostaction.Response{}, p.err
	}
	return p.response, nil
}

func (p *stubPrepared) Release() {}

type stubPreparer struct {
	response hostaction.Response
	err      error
	applyErr error
}

func (p *stubPreparer) Prepare(_ context.Context, req hostaction.CanonicalRequest) (hostaction.Prepared, error) {
	if p.err != nil {
		return nil, p.err
	}
	resp := p.response
	if resp.Class == "" && req.RepoApplyPatch != nil {
		resp = hostaction.Response{
			Class: hostaction.ClassRepoApplyPatchV1,
			RepoApplyPatch: &hostaction.RepoApplyPatchResponse{
				RepoLabel:       req.RepoApplyPatch.Repo.Label,
				AppliedPaths:    append([]string(nil), req.RepoApplyPatch.AffectedPaths...),
				PatchDigest:     req.RepoApplyPatch.PatchDigest,
				PatchDigestAlgo: req.RepoApplyPatch.PatchDigestAlgo,
				BaseRevision:    req.RepoApplyPatch.BaseRevision,
			},
		}
	}
	return &stubPrepared{response: resp, err: p.applyErr}, nil
}

func gitHostActionOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func gitHostActionRawOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
	return string(output)
}

func writeHostActionFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func makeHostPatchRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitHostActionOutput(t, dir, "init")
	gitHostActionOutput(t, dir, "config", "user.email", "aegis@example.com")
	gitHostActionOutput(t, dir, "config", "user.name", "Aegis Test")
	writeHostActionFile(t, filepath.Join(dir, "README.md"), "hello\n")
	gitHostActionOutput(t, dir, "add", "README.md")
	gitHostActionOutput(t, dir, "commit", "-m", "init")
	return dir, gitHostActionOutput(t, dir, "rev-parse", "HEAD")
}

func makeHostPatchDiff(t *testing.T, repoRoot string, relPath string, newBody string) string {
	t.Helper()
	writeHostActionFile(t, filepath.Join(repoRoot, filepath.FromSlash(relPath)), newBody)
	patch := gitHostActionRawOutput(t, repoRoot, "diff", "--", relPath)
	if strings.TrimSpace(patch) == "" {
		t.Fatalf("git diff produced empty patch for %s", relPath)
	}
	gitHostActionOutput(t, repoRoot, "checkout", "--", relPath)
	return patch
}

func hostPatchBrokerRequest(repoLabel string, baseRevision string, patch string) BrokerRequest {
	return BrokerRequest{
		ActionType: governance.ActionHostRepoApply,
		HostAction: &hostaction.Request{
			Class: hostaction.ClassRepoApplyPatchV1,
			RepoApplyPatch: &hostaction.RepoApplyPatchRequest{
				RepoLabel:    repoLabel,
				PatchBase64:  base64.StdEncoding.EncodeToString([]byte(patch)),
				BaseRevision: baseRevision,
			},
		},
	}
}

func signedHostPatchTicket(t *testing.T, privateKey ed25519.PrivateKey, req BrokerRequest, executionID string, policyDigest string) (*approval.SignedTicket, hostaction.CanonicalRequest) {
	t.Helper()
	if req.HostAction == nil {
		t.Fatal("host action is required")
	}
	canonical, err := hostaction.CanonicalizeRequest(*req.HostAction)
	if err != nil {
		t.Fatalf("CanonicalizeRequest: %v", err)
	}
	ticket, err := approval.SignTicket(approval.Ticket{
		Version:      approval.TicketVersion,
		TicketID:     "ticket-host-patch",
		IssuedAt:     time.Unix(100, 0).UTC(),
		ExpiresAt:    time.Unix(200, 0).UTC(),
		Nonce:        "nonce-host-patch",
		ExecutionID:  executionID,
		PolicyDigest: policyDigest,
		ActionType:   governance.ActionHostRepoApply,
		Resource:     canonical.Resource,
	}, privateKey)
	if err != nil {
		t.Fatalf("SignTicket: %v", err)
	}
	return &ticket, canonical
}

func issuedHostPatchLeaseRecord(t *testing.T, privateKey ed25519.PrivateKey, executionID string, policyDigest string, authorityDigest string, repoLabel string) lease.IssuedRecord {
	t.Helper()
	payload, err := lease.BuildExecutionLease(lease.IssueInput{
		Frozen: authority.Context{
			ExecutionID:       executionID,
			PolicyDigest:      policyDigest,
			AuthorityDigest:   authorityDigest,
			BrokerRepoLabels:  []string{repoLabel},
			BrokerActionTypes: []string{governance.ActionHostRepoApply},
			Boot: authority.BootContext{
				RootfsImage: "aegis-rootfs:test",
			},
		},
		Issuer:    "test-issuer",
		IssuedAt:  time.Unix(100, 0).UTC(),
		ExpiresAt: time.Unix(200, 0).UTC(),
		Budgets: lease.BudgetDefaults{
			HostPatchCount: 2,
		},
	})
	if err != nil {
		t.Fatalf("BuildExecutionLease: %v", err)
	}
	signed, err := lease.SignLease(payload, privateKey)
	if err != nil {
		t.Fatalf("SignLease: %v", err)
	}
	keyID := dsse.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	return lease.IssuedRecord{
		LeaseID:         payload.LeaseID,
		ExecutionID:     payload.ExecutionID,
		Issuer:          payload.Issuer,
		IssuerKeyID:     keyID,
		IssuedAt:        payload.IssuedAt,
		ExpiresAt:       payload.ExpiresAt,
		PolicyDigest:    payload.PolicyDigest,
		AuthorityDigest: payload.AuthorityDigest,
		Signed:          signed,
		Lease:           payload,
	}
}

func makeHostPatchBroker(repoLabel string, bus *telemetry.Bus, verifier approval.Verifier, store lease.Store, preparer hostaction.Preparer, leaseVerifier lease.Verifier) *Broker {
	return New(contract.BrokerScope{
		AllowedRepoLabels:  []string{repoLabel},
		AllowedActionTypes: []string{governance.ActionHostRepoApply},
	}, nil, []string{repoLabel}, []string{governance.ActionHostRepoApply}, authority.ApprovalModeNone, "policy-digest", "authority-digest", "test-exec-id", bus, verifier, leaseVerifier, store, preparer)
}

func mustHostRepoResolver(t *testing.T, bindings map[string]string) *hostaction.StaticRepoResolver {
	t.Helper()
	resolver, err := hostaction.NewStaticRepoResolver(bindings)
	if err != nil {
		t.Fatalf("NewStaticRepoResolver: %v", err)
	}
	return resolver
}

func TestBroker_HostRepoApplyPatchDeniedWithoutTicket(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	privateKey := testPrivateKey(9)
	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	b := makeHostPatchBroker("demo", bus, approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	resp := b.Handle(req)
	b.HandleTerminalResponse(resp)
	if !resp.Denied || resp.DenyReason != "broker.approval_ticket_missing" {
		t.Fatalf("response = %+v", resp)
	}
	if got := gitHostActionOutput(t, repoRoot, "status", "--porcelain", "--", "README.md"); got != "" {
		t.Fatalf("repo mutated unexpectedly: %q", got)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Approval == nil || action.Approval.Result != approval.VerificationMissing {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified || action.Lease.BudgetResult != lease.BudgetNotAttempted {
		t.Fatalf("lease = %+v", action.Lease)
	}
	if action.Escalation == nil || !reflect.DeepEqual(action.Escalation.Signals, []escalation.Signal{escalation.SignalDestructiveBoundaryProbe}) {
		t.Fatalf("escalation = %+v", action.Escalation)
	}
	if terminalReason != "" {
		t.Fatalf("terminal reason = %q, want empty", terminalReason)
	}
}

func TestBroker_HostRepoApplyPatchValidTicketAppliesOnce(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(10)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")

	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	bus := telemetry.NewBus("test-exec-id")
	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	b := makeHostPatchBroker("demo", bus, approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	resp := b.Handle(req)
	if !resp.Allowed || resp.Denied {
		t.Fatalf("response = %+v", resp)
	}
	got, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md): %v", err)
	}
	if string(got) != "hello world\n" {
		t.Fatalf("README.md = %q", string(got))
	}
	if len(store.approvalClaims) != 1 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.HostAction == nil || action.HostAction.RepoApplyPatch == nil {
		t.Fatalf("host action evidence = %+v", action.HostAction)
	}
	if action.Approval == nil || action.Approval.Result != approval.VerificationVerified || !action.Approval.Consumed {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified || action.Lease.BudgetResult != lease.BudgetConsumed {
		t.Fatalf("lease = %+v", action.Lease)
	}
}

func TestBroker_HostRepoApplyPatchReusedTicketDenied(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(11)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")

	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	b := makeHostPatchBroker("demo", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	first := b.Handle(req)
	if !first.Allowed {
		t.Fatalf("first response = %+v", first)
	}
	gitHostActionOutput(t, repoRoot, "checkout", "--", "README.md")
	second := b.Handle(req)
	if !second.Denied || second.DenyReason != "broker.approval_ticket_reused" {
		t.Fatalf("second response = %+v", second)
	}
}

func TestBroker_HostRepoApplyPatchWrongResourceBindingDenied(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(12)
	ticket, canonical := signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")
	ticket.Statement.Predicate.Resource = canonical.Resource
	ticket.Statement.Predicate.Resource.HostRepoApplyPatch.RepoLabel = "other"
	signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
	if err != nil {
		t.Fatalf("SignTicket: %v", err)
	}
	req.ApprovalTicket = &signed

	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	b := makeHostPatchBroker("demo", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.approval_ticket_resource_mismatch" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestBroker_HostRepoApplyPatchLeaseSelectorMismatchDenied(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(25)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")

	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "other"))
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	b := makeHostPatchBroker("demo", bus, approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	resp := b.Handle(req)
	b.HandleTerminalResponse(resp)
	if !resp.Denied || resp.DenyReason != "broker.lease_resource_mismatch" {
		t.Fatalf("response = %+v", resp)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Lease == nil || action.Lease.Result != lease.CheckResourceMismatch || action.Lease.BudgetResult != lease.BudgetNotAttempted {
		t.Fatalf("lease = %+v", action.Lease)
	}
	if action.Escalation == nil || !reflect.DeepEqual(action.Escalation.Signals, []escalation.Signal{escalation.SignalAuthorityBroadeningAttempt, escalation.SignalDestructiveBoundaryProbe}) {
		t.Fatalf("escalation = %+v", action.Escalation)
	}
	if terminalReason != escalation.TerminationReasonPrivilegeEscalation {
		t.Fatalf("terminal reason = %q", terminalReason)
	}
}

func TestBroker_HostRepoApplyPatchPolicyDenyDoesNotConsumeTicket(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(13)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")
	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))

	denyBroker := New(contract.BrokerScope{
		AllowedRepoLabels:  []string{"demo"},
		AllowedActionTypes: []string{governance.ActionHTTPRequest},
	}, nil, []string{"demo"}, []string{governance.ActionHTTPRequest}, authority.ApprovalModeNone, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, preparer)
	denyBroker.now = func() time.Time { return time.Unix(150, 0).UTC() }
	denied := denyBroker.Handle(req)
	if !denied.Denied || denied.DenyReason != "governance.action_type_denied" {
		t.Fatalf("denied response = %+v", denied)
	}
	if len(store.approvalClaims) != 0 {
		t.Fatalf("consume calls after deny = %d", len(store.approvalClaims))
	}

	allowBroker := makeHostPatchBroker("demo", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	allowBroker.now = func() time.Time { return time.Unix(150, 0).UTC() }
	allowed := allowBroker.Handle(req)
	if !allowed.Allowed {
		t.Fatalf("allowed response = %+v", allowed)
	}
}

func TestBroker_HostRepoApplyPatchPersistenceUnavailableDenied(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(14)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")

	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	store.consumeErr = lease.ErrLeaseUnavailable
	preparer := hostaction.NewRepoPatchPreparer(mustHostRepoResolver(t, map[string]string{"demo": repoRoot}))
	b := makeHostPatchBroker("demo", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), store, preparer, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.lease_unavailable" {
		t.Fatalf("response = %+v", resp)
	}
	got, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatalf("ReadFile(README.md): %v", err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("README.md = %q", string(got))
	}
}

func TestBroker_HostRepoApplyPatchApplyFailureAfterConsume(t *testing.T) {
	repoRoot, baseRevision := makeHostPatchRepo(t)
	patch := makeHostPatchDiff(t, repoRoot, "README.md", "hello world\n")
	req := hostPatchBrokerRequest("demo", baseRevision, patch)
	privateKey := testPrivateKey(15)
	req.ApprovalTicket, _ = signedHostPatchTicket(t, privateKey, req, "test-exec-id", "policy-digest")

	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	bus := telemetry.NewBus("test-exec-id")
	b := makeHostPatchBroker("demo", bus, approvalVerifierFromPrivateKey(privateKey), store, &stubPreparer{applyErr: fmt.Errorf("apply failed")}, leaseVerifierFromPrivateKey(privateKey))
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	first := b.Handle(req)
	if first.Denied || first.Error == "" {
		t.Fatalf("first response = %+v", first)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Outcome != "error" {
		t.Fatalf("outcome = %q", action.Outcome)
	}
	if action.Approval == nil || action.Approval.Result != approval.VerificationVerified || !action.Approval.Consumed {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified || action.Lease.BudgetResult != lease.BudgetConsumed {
		t.Fatalf("lease = %+v", action.Lease)
	}
	if action.Error == "" {
		t.Fatalf("expected apply failure detail in governed action: %+v", action)
	}

	second := b.Handle(req)
	if !second.Denied || second.DenyReason != "broker.approval_ticket_reused" {
		t.Fatalf("second response = %+v", second)
	}
	if len(store.approvalClaims) != 1 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
}

func TestBroker_HostActionUnsupportedDenied(t *testing.T) {
	privateKey := testPrivateKey(16)
	store := newRecordingLeaseStore(issuedHostPatchLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", "demo"))
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	b := makeHostPatchBroker("demo", bus, nil, store, nil, leaseVerifierFromPrivateKey(privateKey))
	resp := b.Handle(BrokerRequest{
		HostAction: &hostaction.Request{Class: hostaction.ClassHostDockerSocketV1},
	})
	b.HandleTerminalResponse(resp)
	if !resp.Denied || resp.DenyReason != "broker.host_action_unsupported" {
		t.Fatalf("response = %+v", resp)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Escalation == nil || !reflect.DeepEqual(action.Escalation.Signals, []escalation.Signal{escalation.SignalUnsupportedDestructiveClassAccess}) {
		t.Fatalf("escalation = %+v", action.Escalation)
	}
	if terminalReason != escalation.TerminationReasonPrivilegeEscalation {
		t.Fatalf("terminal reason = %q", terminalReason)
	}
}

func TestBroker_HostRepoApplyPatchPathEscapeIsEscalationButNonTerminal(t *testing.T) {
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	b := makeHostPatchBroker("demo", bus, nil, nil, nil, nil)

	patch := strings.Join([]string{
		"diff --git a/../README.md b/../README.md",
		"--- a/../README.md",
		"+++ b/../README.md",
		"@@ -1 +1 @@",
		"-hello",
		"+boom",
		"",
	}, "\n")
	resp := b.Handle(BrokerRequest{
		ActionType: governance.ActionHostRepoApply,
		HostAction: &hostaction.Request{
			Class: hostaction.ClassRepoApplyPatchV1,
			RepoApplyPatch: &hostaction.RepoApplyPatchRequest{
				RepoLabel:    "demo",
				BaseRevision: "deadbeef",
				PatchBase64:  base64.StdEncoding.EncodeToString([]byte(patch)),
			},
		},
	})
	b.HandleTerminalResponse(resp)
	if !resp.Denied || resp.DenyReason != "broker.host_action_path_escape" {
		t.Fatalf("response = %+v", resp)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Escalation == nil || !reflect.DeepEqual(action.Escalation.Signals, []escalation.Signal{escalation.SignalDestructiveBoundaryProbe}) {
		t.Fatalf("escalation = %+v", action.Escalation)
	}
	if terminalReason != "" {
		t.Fatalf("terminal reason = %q, want empty", terminalReason)
	}
}
