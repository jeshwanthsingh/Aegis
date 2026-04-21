package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/dsse"
	"aegis/internal/escalation"
	"aegis/internal/governance"
	"aegis/internal/lease"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

func testPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

type recordingLeaseStore struct {
	records            map[string]lease.IssuedRecord
	remainingByGrantID map[string]uint64
	approvalClaims     []approval.UseClaim
	consumeRequests    []lease.ConsumeRequest
	approvalUsed       map[string]struct{}
	lookupErr          error
	consumeErr         error
	commitErr          error
}

func newRecordingLeaseStore(records ...lease.IssuedRecord) *recordingLeaseStore {
	store := &recordingLeaseStore{
		records:            map[string]lease.IssuedRecord{},
		remainingByGrantID: map[string]uint64{},
		approvalUsed:       map[string]struct{}{},
	}
	for _, record := range records {
		store.records[record.ExecutionID] = record
		for _, grant := range record.Lease.Grants {
			store.remainingByGrantID[grant.GrantID] = grant.Budget.LimitCount
		}
	}
	return store
}

func (s *recordingLeaseStore) PutIssued(_ context.Context, record lease.IssuedRecord) error {
	if s.commitErr != nil {
		return s.commitErr
	}
	if s.records == nil {
		s.records = map[string]lease.IssuedRecord{}
	}
	if s.remainingByGrantID == nil {
		s.remainingByGrantID = map[string]uint64{}
	}
	s.records[record.ExecutionID] = record
	for _, grant := range record.Lease.Grants {
		s.remainingByGrantID[grant.GrantID] = grant.Budget.LimitCount
	}
	return nil
}

func (s *recordingLeaseStore) LookupActiveByExecution(_ context.Context, executionID string) (lease.IssuedRecord, error) {
	if s.lookupErr != nil {
		return lease.IssuedRecord{}, s.lookupErr
	}
	record, ok := s.records[executionID]
	if !ok {
		return lease.IssuedRecord{}, lease.WrapLeaseMissing(executionID)
	}
	return record, nil
}

func (s *recordingLeaseStore) Consume(_ context.Context, req lease.ConsumeRequest) (lease.ConsumeResult, error) {
	if s.consumeErr != nil {
		return lease.ConsumeResult{}, s.consumeErr
	}
	if s.remainingByGrantID == nil {
		s.remainingByGrantID = map[string]uint64{}
	}
	remaining, ok := s.remainingByGrantID[req.GrantID]
	if !ok {
		return lease.ConsumeResult{}, lease.WrapLeaseMissing(req.LeaseID)
	}
	if remaining == 0 {
		return lease.ConsumeResult{}, lease.ErrBudgetExhausted
	}
	var approvalClaim approval.UseClaim
	if req.Approval != nil {
		approvalClaim = *req.Approval
		if _, exists := s.approvalUsed[approvalClaim.TicketID]; exists {
			return lease.ConsumeResult{}, approval.ErrTicketAlreadyUsed
		}
	}
	if s.commitErr != nil {
		return lease.ConsumeResult{}, s.commitErr
	}
	if req.Approval != nil {
		s.approvalUsed[approvalClaim.TicketID] = struct{}{}
		s.approvalClaims = append(s.approvalClaims, approvalClaim)
	}
	s.remainingByGrantID[req.GrantID] = remaining - 1
	s.consumeRequests = append(s.consumeRequests, req)
	return lease.ConsumeResult{RemainingCount: remaining - 1}, nil
}

func approvalVerifierFromPrivateKey(privateKey ed25519.PrivateKey) approval.Verifier {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return approval.NewVerifier(approval.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		dsse.KeyIDFromPublicKey(publicKey): publicKey,
	}))
}

func leaseVerifierFromPrivateKey(privateKey ed25519.PrivateKey) lease.Verifier {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return lease.NewVerifier(lease.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		dsse.KeyIDFromPublicKey(publicKey): publicKey,
	}))
}

func issuedHTTPLeaseRecord(t *testing.T, privateKey ed25519.PrivateKey, executionID string, policyDigest string, authorityDigest string, domains []string, approvalMode authority.ApprovalMode, issuedAt time.Time, expiresAt time.Time) lease.IssuedRecord {
	t.Helper()
	payload, err := lease.BuildExecutionLease(lease.IssueInput{
		Frozen: authority.Context{
			ExecutionID:          executionID,
			PolicyDigest:         policyDigest,
			AuthorityDigest:      authorityDigest,
			BrokerAllowedDomains: append([]string(nil), domains...),
			BrokerActionTypes:    []string{governance.ActionHTTPRequest},
			ApprovalMode:         approvalMode,
			Boot: authority.BootContext{
				RootfsImage: "aegis-rootfs:test",
			},
		},
		Issuer:    "test-issuer",
		IssuedAt:  issuedAt.UTC(),
		ExpiresAt: expiresAt.UTC(),
		Budgets: lease.BudgetDefaults{
			HTTPCount: 5,
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

func signedApprovalTicket(t *testing.T, privateKey ed25519.PrivateKey, req BrokerRequest, executionID string, policyDigest string, actionType string, issuedAt time.Time, expiresAt time.Time) (*approval.SignedTicket, approval.CanonicalResource) {
	t.Helper()
	resource, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    decodeBodyForTest(t, req.BodyBase64),
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	ticket, err := approval.SignTicket(approval.Ticket{
		Version:      approval.TicketVersion,
		TicketID:     "ticket-" + strings.ReplaceAll(actionType, "_", "-"),
		IssuedAt:     issuedAt.UTC(),
		ExpiresAt:    expiresAt.UTC(),
		Nonce:        "nonce-" + actionType,
		ExecutionID:  executionID,
		PolicyDigest: policyDigest,
		ActionType:   actionType,
		Resource:     resource.Resource,
	}, privateKey)
	if err != nil {
		t.Fatalf("SignTicket: %v", err)
	}
	return &ticket, resource
}

func decodeBodyForTest(t *testing.T, raw string) []byte {
	t.Helper()
	body, err := decodeRequestBody(raw)
	if err != nil {
		t.Fatalf("decodeRequestBody: %v", err)
	}
	return body
}

func governedActionFromEvents(t *testing.T, events []telemetry.Event) telemetry.GovernedActionData {
	t.Helper()
	for _, event := range events {
		if event.Kind != telemetry.KindGovernedAction {
			continue
		}
		var data telemetry.GovernedActionData
		if err := json.Unmarshal(event.Data, &data); err != nil {
			t.Fatalf("json.Unmarshal(governed action): %v", err)
		}
		return data
	}
	t.Fatal("missing governed.action.v1 event")
	return telemetry.GovernedActionData{}
}

func TestBroker_ValidTicketAllowsRequestAndEmitsVerifiedApproval(t *testing.T) {
	privateKey := testPrivateKey(1)
	bus := telemetry.NewBus("test-exec-id")
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", bus, approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	resp := b.Handle(req)
	if !resp.Allowed || resp.Denied {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d", requestCount)
	}
	if len(store.approvalClaims) != 1 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Approval == nil || action.Approval.Result != approval.VerificationVerified {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Approval.TicketID == "" || action.Approval.ResourceDigest == "" {
		t.Fatalf("approval evidence = %+v", action.Approval)
	}
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified || action.Lease.BudgetResult != lease.BudgetConsumed {
		t.Fatalf("lease = %+v", action.Lease)
	}
}

func TestBroker_MissingTicketDenied(t *testing.T) {
	privateKey := testPrivateKey(2)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", bus, approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	grantID := store.records["test-exec-id"].Lease.Grants[0].GrantID

	resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"})
	b.HandleTerminalResponse(resp)
	if !resp.Denied || resp.DenyReason != "broker.approval_ticket_missing" {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 0 {
		t.Fatalf("request count = %d", requestCount)
	}
	if len(store.approvalClaims) != 0 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
	if got, want := store.remainingByGrantID[grantID], uint64(5); got != want {
		t.Fatalf("remaining count = %d, want %d", got, want)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Approval == nil || action.Approval.Result != approval.VerificationMissing {
		t.Fatalf("approval = %+v", action.Approval)
	}
	if action.Lease == nil || action.Lease.Result != lease.CheckVerified || action.Lease.BudgetResult != lease.BudgetNotAttempted {
		t.Fatalf("lease = %+v", action.Lease)
	}
	if action.Escalation != nil {
		t.Fatalf("escalation = %+v, want nil", action.Escalation)
	}
	if terminalReason != "" {
		t.Fatalf("terminal reason = %q, want empty", terminalReason)
	}
}

func TestBroker_HTTPLeaseSelectorMismatchBecomesRepeatedProbingAtThreshold(t *testing.T) {
	privateKey := testPrivateKey(31)
	allowed := []string{"a.example.com", "b.example.com", "c.example.com"}
	bus := telemetry.NewBus("test-exec-id")
	var terminalReason string
	bus.ConfigureEscalation(escalation.NewTracker(), func(reason string) { terminalReason = reason })
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{"allow.example.com"}, authority.ApprovalModeNone, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: allowed,
	}, allowed, nil, nil, authority.ApprovalModeNone, "policy-digest", "authority-digest", "test-exec-id", bus, approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }

	urls := []string{
		"https://a.example.com/v1",
		"https://b.example.com/v1",
		"https://c.example.com/v1",
	}
	for idx, rawURL := range urls {
		resp := b.Handle(BrokerRequest{Method: http.MethodGet, URL: rawURL})
		b.HandleTerminalResponse(resp)
		if !resp.Denied || resp.DenyReason != "broker.lease_resource_mismatch" {
			t.Fatalf("response %d = %+v", idx, resp)
		}
		action := governedActionFromEvents(t, bus.Drain())
		switch idx {
		case 0, 1:
			if action.Escalation != nil {
				t.Fatalf("action %d escalation = %+v, want nil", idx, action.Escalation)
			}
			if terminalReason != "" {
				t.Fatalf("terminal reason after %d = %q, want empty", idx, terminalReason)
			}
		case 2:
			if action.Escalation == nil || !reflect.DeepEqual(action.Escalation.Signals, []escalation.Signal{escalation.SignalRepeatedProbingPattern}) {
				t.Fatalf("action %d escalation = %+v", idx, action.Escalation)
			}
			if terminalReason != escalation.TerminationReasonPrivilegeEscalation {
				t.Fatalf("terminal reason after %d = %q", idx, terminalReason)
			}
		}
	}
}

func TestBroker_MissingLeaseDenied(t *testing.T) {
	privateKey := testPrivateKey(22)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	bus := telemetry.NewBus("test-exec-id")
	store := newRecordingLeaseStore()
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", bus, approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.lease_missing" {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 0 {
		t.Fatalf("request count = %d", requestCount)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Lease == nil || action.Lease.Result != lease.CheckMissing || action.Lease.BudgetResult != lease.BudgetNotAttempted {
		t.Fatalf("lease = %+v", action.Lease)
	}
}

func TestBroker_ExpiredLeaseDenied(t *testing.T) {
	privateKey := testPrivateKey(23)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	bus := telemetry.NewBus("test-exec-id")
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(140, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", bus, approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.lease_expired" {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 0 {
		t.Fatalf("request count = %d", requestCount)
	}
	action := governedActionFromEvents(t, bus.Drain())
	if action.Lease == nil || action.Lease.Result != lease.CheckExpired || action.Lease.BudgetResult != lease.BudgetNotAttempted {
		t.Fatalf("lease = %+v", action.Lease)
	}
}

func TestBroker_TicketVerificationFailuresDenied(t *testing.T) {
	privateKey := testPrivateKey(3)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	req := BrokerRequest{Method: http.MethodPost, URL: "https://api.example.com/v1/items", Headers: map[string][]string{"Content-Type": {"application/json"}}}
	baseTicket, resource := signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	makeBroker := func(verifier approval.Verifier) *Broker {
		store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{"api.example.com"}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
		return New(contract.BrokerScope{
			AllowedDomains: []string{"api.example.com"},
		}, []string{"api.example.com"}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), verifier, leaseVerifierFromPrivateKey(privateKey), store, nil)
	}

	tests := []struct {
		name       string
		mutate     func(ticket *approval.SignedTicket)
		verifier   approval.Verifier
		denyReason string
	}{
		{
			name:     "expired",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Statement.Predicate.ExpiresAt = time.Unix(120, 0).UTC()
				signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
				if err != nil {
					t.Fatalf("SignTicket(expired): %v", err)
				}
				*ticket = signed
			},
			denyReason: "broker.approval_ticket_expired",
		},
		{
			name:     "wrong_execution",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Statement.Predicate.ExecutionID = "other-exec"
				signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
				if err != nil {
					t.Fatalf("SignTicket(wrong_execution): %v", err)
				}
				*ticket = signed
			},
			denyReason: "broker.approval_ticket_execution_mismatch",
		},
		{
			name:     "wrong_policy",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Statement.Predicate.PolicyDigest = "other-policy"
				signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
				if err != nil {
					t.Fatalf("SignTicket(wrong_policy): %v", err)
				}
				*ticket = signed
			},
			denyReason: "broker.approval_ticket_policy_mismatch",
		},
		{
			name:     "wrong_action",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Statement.Predicate.ActionType = governance.ActionDependencyFetch
				signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
				if err != nil {
					t.Fatalf("SignTicket(wrong_action): %v", err)
				}
				*ticket = signed
			},
			denyReason: "broker.approval_ticket_action_type_mismatch",
		},
		{
			name:     "wrong_resource",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Statement.Predicate.Resource = resource.Resource
				ticket.Statement.Predicate.Resource.HTTP.URL = "https://api.example.com/v1/items?other=true"
				signed, err := approval.SignTicket(ticket.Statement.Predicate, privateKey)
				if err != nil {
					t.Fatalf("SignTicket(wrong_resource): %v", err)
				}
				*ticket = signed
			},
			denyReason: "broker.approval_ticket_resource_mismatch",
		},
		{
			name:     "malformed_dsse",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Envelope.Payload = "%%%bad%%%"
			},
			denyReason: "broker.approval_ticket_malformed",
		},
		{
			name:     "bad_signature",
			verifier: approvalVerifierFromPrivateKey(privateKey),
			mutate: func(ticket *approval.SignedTicket) {
				ticket.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString([]byte("wrong"))
			},
			denyReason: "broker.approval_ticket_signature_invalid",
		},
		{
			name:       "unknown_key",
			verifier:   approval.NewVerifier(approval.NewStaticKeyResolver(map[string]ed25519.PublicKey{})),
			mutate:     func(ticket *approval.SignedTicket) {},
			denyReason: "broker.approval_ticket_signature_invalid",
		},
		{
			name: "invalid_signature",
			verifier: approval.NewVerifier(approval.NewStaticKeyResolver(map[string]ed25519.PublicKey{
				dsse.KeyIDFromPublicKey(publicKey): testPrivateKey(4).Public().(ed25519.PublicKey),
			})),
			mutate:     func(ticket *approval.SignedTicket) {},
			denyReason: "broker.approval_ticket_signature_invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticket := *baseTicket
			tt.mutate(&ticket)
			b := makeBroker(tt.verifier)
			b.now = func() time.Time { return time.Unix(150, 0).UTC() }
			resp := b.Handle(BrokerRequest{
				Method:         req.Method,
				URL:            req.URL,
				Headers:        req.Headers,
				ApprovalTicket: &ticket,
			})
			if !resp.Denied || resp.DenyReason != tt.denyReason {
				t.Fatalf("response = %+v", resp)
			}
		})
	}
}

func TestBroker_ReusedTicketDeniedOnSecondUse(t *testing.T) {
	privateKey := testPrivateKey(5)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	grantID := store.records["test-exec-id"].Lease.Grants[0].GrantID
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	first := b.Handle(req)
	if !first.Allowed {
		t.Fatalf("first response = %+v", first)
	}
	if got, want := store.remainingByGrantID[grantID], uint64(4); got != want {
		t.Fatalf("remaining count after first use = %d, want %d", got, want)
	}
	second := b.Handle(req)
	if !second.Denied || second.DenyReason != "broker.approval_ticket_reused" {
		t.Fatalf("second response = %+v", second)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d", requestCount)
	}
	if got, want := store.remainingByGrantID[grantID], uint64(4); got != want {
		t.Fatalf("remaining count after reuse = %d, want %d", got, want)
	}
}

func TestBroker_PolicyDenyDoesNotConsumeTicket(t *testing.T) {
	privateKey := testPrivateKey(6)
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{"api.example.com"}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains:     []string{"api.example.com"},
		AllowedActionTypes: []string{governance.ActionDependencyFetch},
	}, []string{"api.example.com"}, nil, []string{governance.ActionDependencyFetch}, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	grantID := store.records["test-exec-id"].Lease.Grants[0].GrantID
	req := BrokerRequest{Method: http.MethodGet, URL: "https://api.example.com/v1/data", ActionType: governance.ActionHTTPRequest}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "governance.action_type_denied" {
		t.Fatalf("response = %+v", resp)
	}
	if len(store.approvalClaims) != 0 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
	if got, want := store.remainingByGrantID[grantID], uint64(5); got != want {
		t.Fatalf("remaining count = %d, want %d", got, want)
	}
}

func TestBroker_LeaseBudgetExhaustedDenied(t *testing.T) {
	privateKey := testPrivateKey(24)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	grantID := store.records["test-exec-id"].Lease.Grants[0].GrantID
	store.remainingByGrantID[grantID] = 0
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.lease_budget_exhausted" {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 0 {
		t.Fatalf("request count = %d", requestCount)
	}
	if len(store.approvalClaims) != 0 {
		t.Fatalf("approval claims = %d", len(store.approvalClaims))
	}
	if got := store.remainingByGrantID[grantID]; got != 0 {
		t.Fatalf("remaining count = %d, want 0", got)
	}
}

func TestBroker_UpstreamFailureLeavesTicketSpent(t *testing.T) {
	privateKey := testPrivateKey(7)
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{"127.0.0.1"}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	b := New(contract.BrokerScope{
		AllowedDomains: []string{"127.0.0.1"},
	}, []string{"127.0.0.1"}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	req := BrokerRequest{Method: http.MethodGet, URL: "http://127.0.0.1:1/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	first := b.Handle(req)
	if first.Error == "" || first.Denied {
		t.Fatalf("first response = %+v", first)
	}
	second := b.Handle(req)
	if !second.Denied || second.DenyReason != "broker.approval_ticket_reused" {
		t.Fatalf("second response = %+v", second)
	}
	if len(store.approvalClaims) != 1 {
		t.Fatalf("consume calls = %d", len(store.approvalClaims))
	}
}

func TestBroker_PersistenceUnavailableDeniedWithoutSideEffect(t *testing.T) {
	privateKey := testPrivateKey(8)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	store := newRecordingLeaseStore(issuedHTTPLeaseRecord(t, privateKey, "test-exec-id", "policy-digest", "authority-digest", []string{host}, authority.ApprovalModeRequireHostConsent, time.Unix(100, 0), time.Unix(200, 0)))
	store.consumeErr = lease.ErrLeaseUnavailable
	b := New(contract.BrokerScope{
		AllowedDomains: []string{host},
	}, []string{host}, nil, nil, authority.ApprovalModeRequireHostConsent, "policy-digest", "authority-digest", "test-exec-id", telemetry.NewBus("test-exec-id"), approvalVerifierFromPrivateKey(privateKey), leaseVerifierFromPrivateKey(privateKey), store, nil)
	b.now = func() time.Time { return time.Unix(150, 0).UTC() }
	req := BrokerRequest{Method: http.MethodGet, URL: srv.URL + "/v1/data"}
	req.ApprovalTicket, _ = signedApprovalTicket(t, privateKey, req, "test-exec-id", "policy-digest", governance.ActionHTTPRequest, time.Unix(100, 0), time.Unix(200, 0))

	resp := b.Handle(req)
	if !resp.Denied || resp.DenyReason != "broker.lease_unavailable" {
		t.Fatalf("response = %+v", resp)
	}
	if requestCount != 0 {
		t.Fatalf("request count = %d", requestCount)
	}
}
