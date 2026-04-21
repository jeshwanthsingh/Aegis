package broker

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"aegis/internal/approval"
	"aegis/internal/authority"
	"aegis/internal/escalation"
	"aegis/internal/governance"
	"aegis/internal/hostaction"
	"aegis/internal/lease"
	"aegis/internal/observability"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

const (
	brokerHTTPTimeout = 30 * time.Second

	// responseHeaderDenylist are headers stripped before returning the response to the guest.
	// These must never be echoed back as they may contain auth material set by the host.
	responseHeaderDenylist = "authorization,set-cookie,cookie,x-amz-security-token,x-goog-auth"
)

// Broker validates and executes brokered outbound requests on behalf of the guest.
// The guest never receives raw long-lived credential values.
type Broker struct {
	scope            contract.BrokerScope
	execID           string
	bus              *telemetry.Bus
	client           *http.Client
	approvalMode     authority.ApprovalMode
	policyDigest     string
	authorityDigest  string
	approvalVerifier approval.Verifier
	leaseVerifier    lease.Verifier
	leaseStore       lease.Store
	hostActions      hostaction.Preparer
	now              func() time.Time
}

// New constructs a Broker for a single execution.
func New(scope contract.BrokerScope, allowedDomains []string, allowedRepoLabels []string, actionTypes []string, approvalMode authority.ApprovalMode, policyDigest string, authorityDigest string, execID string, bus *telemetry.Bus, approvalVerifier approval.Verifier, leaseVerifier lease.Verifier, leaseStore lease.Store, hostActions hostaction.Preparer) *Broker {
	scope.AllowedDomains = append([]string(nil), allowedDomains...)
	scope.AllowedRepoLabels = append([]string(nil), allowedRepoLabels...)
	scope.AllowedActionTypes = append([]string(nil), actionTypes...)
	scope.RequireHostConsent = approvalMode == authority.ApprovalModeRequireHostConsent
	return &Broker{
		scope:            scope,
		execID:           execID,
		bus:              bus,
		client:           &http.Client{Timeout: brokerHTTPTimeout},
		approvalMode:     approvalMode,
		policyDigest:     strings.TrimSpace(policyDigest),
		authorityDigest:  strings.TrimSpace(authorityDigest),
		approvalVerifier: approvalVerifier,
		leaseVerifier:    leaseVerifier,
		leaseStore:       leaseStore,
		hostActions:      hostActions,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

// Handle validates a BrokerRequest and, if allowed, performs the outbound HTTP request
// with host-side credential injection. The raw credential value is never returned to the guest.
func (b *Broker) Handle(req BrokerRequest) BrokerResponse {
	if req.HostAction != nil {
		return b.handleHostAction(req)
	}
	return b.handleHTTP(req)
}

func (b *Broker) handleHTTP(req BrokerRequest) BrokerResponse {
	actionType := governance.NormalizeActionType(req.ActionType)
	if actionType == "" {
		actionType = governance.ActionHTTPRequest
	}
	target := governance.SanitizeTarget(req.URL)

	// Emit request event regardless of outcome.
	domain, domainErr := extractDomain(req.URL)
	b.emit(telemetry.KindCredentialRequest, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		TargetDomain: domain,
		Method:       req.Method,
		ActionType:   actionType,
		Outcome:      "pending",
	})

	// Reject CONNECT tunneling: host cannot inject auth headers into opaque TLS streams.
	if strings.ToUpper(req.Method) == http.MethodConnect {
		return b.deny(governance.CapabilityRecord{
			Request: governance.Request{
				ExecutionID: b.execID,
				ActionType:  actionType,
				Method:      strings.ToUpper(req.Method),
				Target:      target,
				Resource:    domain,
				Brokered:    true,
			},
			Decision: governance.Decision{
				Deny:         true,
				RuleID:       "broker.connect_not_supported",
				Reason:       "CONNECT tunneling is not supported in v1; use plain HTTP requests",
				PolicyDigest: b.policyDigest,
				AuditPayload: map[string]string{"target_domain": domain},
			},
			Use: governance.CapabilityUse{
				Path: governance.CapabilityPathBroker,
			},
		}, "", nil)
	}

	body, err := decodeRequestBody(req.BodyBase64)
	if err != nil {
		b.emit(telemetry.KindCredentialError, telemetry.CredentialBrokerData{
			ExecutionID:  b.execID,
			TargetDomain: domain,
			Method:       req.Method,
			ActionType:   actionType,
			Outcome:      "error",
			DenialReason: err.Error(),
		})
		return BrokerResponse{Error: fmt.Sprintf("broker request failed: %v", err)}
	}

	resource, err := approval.CanonicalizeHTTPRequest(approval.HTTPRequestInput{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    body,
	})
	if err != nil {
		return b.denyError(target, actionType, b.policyDigest, "broker.invalid_url", fmt.Sprintf("invalid URL: %v", err), nil)
	}
	target = governance.SanitizeTarget(resource.Resource.HTTP.URL)

	if domainErr != nil {
		return b.denyError(target, actionType, b.policyDigest, "broker.invalid_url", fmt.Sprintf("invalid URL: %v", domainErr), nil)
	}
	record := governance.EvaluateBrokerCapability(b.scope, governance.Request{
		ExecutionID: b.execID,
		ActionType:  actionType,
		Method:      resource.Resource.HTTP.Method,
		Target:      target,
		Resource:    domain,
		Brokered:    true,
	})
	record.Decision.PolicyDigest = b.policyDigest
	record.Decision.AuditPayload = mergeAuditPayload(record.Decision.AuditPayload, approval.ResourceToAuditPayload(resource.Resource))
	if record.Decision.Deny {
		return b.deny(record, "", nil)
	}

	// Find the first loaded credential binding from allowed delegations.
	binding, bindingName := b.resolveBinding()
	if len(b.scope.AllowedDelegations) > 0 && !binding.IsLoaded() {
		record.Decision.Allow = false
		record.Decision.Deny = true
		record.Decision.RuleID = "broker.binding_unavailable"
		record.Decision.Reason = "no configured host credential matched broker_scope.allowed_delegations"
		record.Use.BindingName = ""
		return b.deny(record, "", nil)
	}

	leaseKind, ok := leaseActionKind(actionType)
	if !ok {
		leaseCheck := &lease.Check{
			Required:     true,
			Result:       lease.CheckActionMismatch,
			Reason:       "broker.lease_action_kind_unsupported",
			BudgetResult: lease.BudgetNotAttempted,
		}
		return b.deny(withLeaseFailure(record, *leaseCheck, fmt.Sprintf("lease action kind %q is not supported in v1", actionType)), "", leaseCheck)
	}
	leaseCheck, verifiedLease, deniedResp := b.verifyLease(record, leaseKind, resource.Resource)
	if deniedResp != nil {
		return *deniedResp
	}
	record.Use.Lease = leaseCheck

	var approvalCheck *approval.Check
	var verifiedApproval approval.VerifiedTicket
	if b.approvalMode == authority.ApprovalModeRequireHostConsent {
		approvalCheck, verifiedApproval, deniedResp = b.verifyApprovalTicket(record, req.ApprovalTicket, actionType, resource.Resource, resource.ResourceDigest, resource.ResourceDigestAlgo, "host consent requires a signed approval ticket")
		if deniedResp != nil {
			return *deniedResp
		}
		record.Use.Approval = approvalCheck
	}

	consumeResp, deniedResp := b.consumeLeaseAndApproval(record, leaseCheck, verifiedLease, approvalCheck, verifiedApproval, actionType)
	if deniedResp != nil {
		return *deniedResp
	}
	if leaseCheck != nil {
		leaseCheck.BudgetResult = lease.BudgetConsumed
		remaining := consumeResp.RemainingCount
		leaseCheck.RemainingCount = &remaining
	}
	if approvalCheck != nil {
		approvalCheck.Consumed = true
	}

	// Perform the outbound HTTP request with credential injection.
	resp, responseDigest, err := b.execute(resource, binding)
	if err != nil {
		b.emit(telemetry.KindCredentialError, telemetry.CredentialBrokerData{
			ExecutionID:  b.execID,
			BindingName:  bindingName,
			TargetDomain: domain,
			Method:       req.Method,
			ActionType:   actionType,
			Outcome:      "error",
			DenialReason: err.Error(),
		})
		record.Use.BindingName = bindingName
		record.Use.CredentialsInjected = binding.IsLoaded()
		record.Use.Error = err.Error()
		record.Use.Approval = approvalCheck
		record.Use.Lease = leaseCheck
		record.Decision.Reason = "governed action allowed but upstream execution failed"
		b.emitGovernedAction(record.ToGovernedActionData())
		return BrokerResponse{Error: fmt.Sprintf("broker request failed: %v", err)}
	}

	b.emit(telemetry.KindCredentialAllowed, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		BindingName:  bindingName,
		TargetDomain: domain,
		Method:       req.Method,
		ActionType:   actionType,
		Outcome:      "allowed",
	})
	record.Use.BindingName = bindingName
	record.Use.CredentialsInjected = binding.IsLoaded()
	record.Use.ResponseDigest = responseDigest
	record.Use.ResponseDigestAlgo = "sha256"
	record.Use.Approval = approvalCheck
	record.Use.Lease = leaseCheck
	record.Use.Used = true
	b.emitGovernedAction(record.ToGovernedActionData())

	return resp
}

func (b *Broker) handleHostAction(req BrokerRequest) BrokerResponse {
	actionType := hostActionActionType(req.HostAction)
	if actionType == "" {
		actionType = governance.NormalizeActionType(req.ActionType)
	}
	if actionType == "" {
		actionType = governance.ActionHostRepoApply
	}

	canonical, err := hostaction.CanonicalizeRequest(*req.HostAction)
	if err != nil {
		return b.denyHostActionError(req.HostAction, actionType, err)
	}

	target := "repo:" + canonical.RepoApplyPatch.Repo.Label
	resourceLabel := canonical.RepoApplyPatch.Repo.Label
	record := governance.EvaluateBrokerCapability(b.scope, governance.Request{
		ExecutionID: b.execID,
		ActionType:  actionType,
		Target:      target,
		Resource:    resourceLabel,
		Brokered:    true,
	})
	record.Decision.PolicyDigest = b.policyDigest
	record.Decision.AuditPayload = mergeAuditPayload(
		record.Decision.AuditPayload,
		approval.ResourceToAuditPayload(canonical.Resource),
		hostActionAuditPayload(canonical.Evidence),
	)
	record.Use.HostAction = canonical.Evidence
	if record.Decision.Deny {
		return b.deny(record, "", nil)
	}

	leaseCheck, verifiedLease, deniedResp := b.verifyLease(record, lease.ActionKindHostRepoApplyPatch, canonical.Resource)
	if deniedResp != nil {
		return *deniedResp
	}
	record.Use.Lease = leaseCheck

	approvalCheck, verifiedApproval, deniedResp := b.verifyApprovalTicket(record, req.ApprovalTicket, actionType, canonical.Resource, canonical.ResourceDigest, canonical.ResourceDigestAlgo, "host repo apply requires a signed approval ticket")
	if deniedResp != nil {
		return *deniedResp
	}
	record.Use.Approval = approvalCheck

	if b.hostActions == nil {
		return b.deny(withHostActionFailure(record, approvalCheck, leaseCheck, hostaction.NewError("broker.host_action_unsupported", map[string]string{"host_action_class": string(canonical.Class)}, "host action class %q is not configured", canonical.Class)), "", nil)
	}
	prepared, err := b.hostActions.Prepare(context.Background(), canonical)
	if err != nil {
		return b.deny(withHostActionFailure(record, approvalCheck, leaseCheck, err), "", nil)
	}
	defer prepared.Release()
	consumeResp, deniedResp := b.consumeLeaseAndApproval(record, leaseCheck, verifiedLease, approvalCheck, verifiedApproval, actionType)
	if deniedResp != nil {
		return *deniedResp
	}
	leaseCheck.BudgetResult = lease.BudgetConsumed
	remaining := consumeResp.RemainingCount
	leaseCheck.RemainingCount = &remaining
	approvalCheck.Consumed = true

	resp, err := prepared.Apply(context.Background())
	if err != nil {
		record.Use.Error = err.Error()
		record.Use.Approval = approvalCheck
		record.Use.Lease = leaseCheck
		record.Use.HostAction = canonical.Evidence
		record.Decision.Reason = "governed action allowed but host apply failed"
		b.emitGovernedAction(record.ToGovernedActionData())
		return BrokerResponse{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Sprintf("broker request failed: %v", err),
		}
	}

	record.Use.Approval = approvalCheck
	record.Use.Lease = leaseCheck
	record.Use.HostAction = canonical.Evidence
	record.Use.Used = true
	b.emitGovernedAction(record.ToGovernedActionData())
	return BrokerResponse{
		StatusCode: http.StatusOK,
		Allowed:    true,
		HostAction: &resp,
	}
}

func (b *Broker) verifyApprovalTicket(record governance.CapabilityRecord, ticket *approval.SignedTicket, actionType string, resource approval.Resource, resourceDigest string, resourceDigestAlgo string, missingDetail string) (*approval.Check, approval.VerifiedTicket, *BrokerResponse) {
	if b.approvalVerifier == nil {
		resp := b.deny(withApprovalFailure(record, approval.Check{
			Required:           true,
			Result:             approval.VerificationUnavailable,
			Reason:             "broker.approval_ticket_unavailable",
			ResourceDigest:     resourceDigest,
			ResourceDigestAlgo: resourceDigestAlgo,
		}, "approval ticket verification is unavailable"), "", nil)
		return nil, approval.VerifiedTicket{}, &resp
	}
	if ticket == nil {
		resp := b.deny(withApprovalFailure(record, approval.Check{
			Required:           true,
			Result:             approval.VerificationMissing,
			Reason:             "broker.approval_ticket_missing",
			ResourceDigest:     resourceDigest,
			ResourceDigestAlgo: resourceDigestAlgo,
		}, missingDetail), "", nil)
		return nil, approval.VerifiedTicket{}, &resp
	}
	verified, err := b.approvalVerifier.Verify(context.Background(), *ticket, approval.VerificationRequest{
		ExecutionID:  b.execID,
		PolicyDigest: b.policyDigest,
		ActionType:   actionType,
		Resource:     resource,
		Now:          b.now(),
	})
	if err != nil {
		result, reason, ok := approval.VerificationFailure(err)
		if !ok {
			result = approval.VerificationUnavailable
			reason = "broker.approval_ticket_unavailable"
		}
		ticketCheck := approval.Check{
			Required:           true,
			Result:             result,
			Reason:             reason,
			ResourceDigest:     resourceDigest,
			ResourceDigestAlgo: resourceDigestAlgo,
		}
		resp := b.deny(withApprovalFailure(record, ticketCheck, verificationDetail(reason, err)), "", nil)
		return nil, approval.VerifiedTicket{}, &resp
	}
	approvalCheck := &approval.Check{
		Required:           true,
		TicketID:           verified.Ticket.TicketID,
		IssuerKeyID:        verified.IssuerKeyID,
		Result:             approval.VerificationVerified,
		ExpiresAt:          verified.Ticket.ExpiresAt.UTC(),
		ResourceDigest:     verified.ResourceDigest,
		ResourceDigestAlgo: verified.ResourceDigestAlgo,
	}
	return approvalCheck, verified, nil
}

func (b *Broker) verifyLease(record governance.CapabilityRecord, actionKind lease.ActionKind, resource approval.Resource) (*lease.Check, lease.VerifiedLease, *BrokerResponse) {
	check := &lease.Check{
		Required:     true,
		Result:       lease.CheckUnavailable,
		BudgetResult: lease.BudgetNotAttempted,
	}
	if b.leaseStore == nil || b.leaseVerifier == nil {
		check.Reason = "broker.lease_unavailable"
		resp := b.deny(withLeaseFailure(record, *check, "lease verification is unavailable"), "", check)
		return nil, lease.VerifiedLease{}, &resp
	}
	issued, err := b.leaseStore.LookupActiveByExecution(context.Background(), b.execID)
	if err != nil {
		if lease.IsLeaseMissing(err) {
			check.Result = lease.CheckMissing
			check.Reason = "broker.lease_missing"
			resp := b.deny(withLeaseFailure(record, *check, "execution does not have an active lease"), "", check)
			return nil, lease.VerifiedLease{}, &resp
		}
		check.Reason = "broker.lease_unavailable"
		resp := b.deny(withLeaseFailure(record, *check, "lease lookup is unavailable"), "", check)
		return nil, lease.VerifiedLease{}, &resp
	}
	verified, err := b.leaseVerifier.Verify(context.Background(), issued.Signed, lease.VerificationRequest{
		ExecutionID:     b.execID,
		PolicyDigest:    b.policyDigest,
		AuthorityDigest: b.authorityDigest,
		ActionKind:      actionKind,
		Resource:        resource,
		Now:             b.now(),
	})
	if err != nil {
		result, reason, ok := lease.VerificationFailure(err)
		if !ok {
			result = lease.CheckUnavailable
			reason = "broker.lease_unavailable"
		}
		check.Result = result
		check.Reason = reason
		resp := b.deny(withLeaseFailure(record, *check, leaseVerificationDetail(reason, err)), "", check)
		return nil, lease.VerifiedLease{}, &resp
	}
	check.LeaseID = verified.Lease.LeaseID
	check.Issuer = verified.Lease.Issuer
	check.IssuerKeyID = verified.IssuerKeyID
	check.Result = lease.CheckVerified
	check.ExpiresAt = verified.Lease.ExpiresAt.UTC()
	check.GrantID = verified.Grant.GrantID
	check.SelectorDigest = verified.SelectorDigest
	check.SelectorDigestAlgo = verified.SelectorDigestAlgo
	return check, verified, nil
}

func (b *Broker) consumeLeaseAndApproval(record governance.CapabilityRecord, leaseCheck *lease.Check, verifiedLease lease.VerifiedLease, approvalCheck *approval.Check, verifiedApproval approval.VerifiedTicket, actionType string) (lease.ConsumeResult, *BrokerResponse) {
	if leaseCheck == nil {
		return lease.ConsumeResult{}, nil
	}
	if b.leaseStore == nil {
		leaseCheck.Result = lease.CheckUnavailable
		leaseCheck.Reason = "broker.lease_unavailable"
		leaseCheck.BudgetResult = lease.BudgetUnavailable
		resp := b.deny(withLeaseFailure(record, *leaseCheck, "lease persistence is unavailable"), "", leaseCheck)
		return lease.ConsumeResult{}, &resp
	}
	req := lease.ConsumeRequest{
		LeaseID:    verifiedLease.Lease.LeaseID,
		GrantID:    verifiedLease.Grant.GrantID,
		ConsumedAt: b.now(),
	}
	if approvalCheck != nil {
		req.Approval = &approval.UseClaim{
			TicketID:           verifiedApproval.Ticket.TicketID,
			Nonce:              verifiedApproval.Ticket.Nonce,
			ExecutionID:        b.execID,
			PolicyDigest:       b.policyDigest,
			ActionType:         actionType,
			ResourceDigest:     verifiedApproval.ResourceDigest,
			ResourceDigestAlgo: verifiedApproval.ResourceDigestAlgo,
			ConsumedAt:         b.now(),
		}
	}
	result, err := b.leaseStore.Consume(context.Background(), req)
	if err == nil {
		return result, nil
	}
	if approvalCheck != nil && approval.IsTicketAlreadyUsed(err) {
		approvalCheck.Result = approval.VerificationReused
		approvalCheck.Reason = "broker.approval_ticket_reused"
		leaseCheck.BudgetResult = lease.BudgetNotAttempted
		record = withLeaseFailure(record, *leaseCheck, "lease budget was not consumed")
		resp := b.deny(withApprovalFailure(record, *approvalCheck, "approval ticket was already used"), "", leaseCheck)
		return lease.ConsumeResult{}, &resp
	}
	if lease.IsBudgetExhausted(err) {
		leaseCheck.BudgetResult = lease.BudgetExhausted
		leaseCheck.Reason = "broker.lease_budget_exhausted"
		resp := b.deny(withLeaseFailure(record, *leaseCheck, "lease budget was exhausted"), "", leaseCheck)
		return lease.ConsumeResult{}, &resp
	}
	leaseCheck.Result = lease.CheckUnavailable
	leaseCheck.Reason = "broker.lease_unavailable"
	leaseCheck.BudgetResult = lease.BudgetUnavailable
	resp := b.deny(withLeaseFailure(record, *leaseCheck, "lease persistence is unavailable"), "", leaseCheck)
	return lease.ConsumeResult{}, &resp
}

// AllowedDomains returns the configured allowed domains for external use (e.g. divergence tracking).
func (b *Broker) AllowedDomains() []string {
	return append([]string(nil), b.scope.AllowedDomains...)
}

func (b *Broker) AllowedRepoLabels() []string {
	return append([]string(nil), b.scope.AllowedRepoLabels...)
}

func (b *Broker) AllowedActionTypes() []string {
	return append([]string(nil), b.scope.AllowedActionTypes...)
}

func (b *Broker) ApprovalMode() authority.ApprovalMode {
	return b.approvalMode
}

func (b *Broker) resolveBinding() (CredentialBinding, string) {
	for _, name := range b.scope.AllowedDelegations {
		if binding, ok := LoadBinding(name); ok {
			return binding, name
		}
	}
	return CredentialBinding{}, ""
}

func (b *Broker) execute(resource approval.CanonicalResource, binding CredentialBinding) (BrokerResponse, string, error) {
	var body io.Reader
	if len(resource.Body) > 0 {
		body = strings.NewReader(string(resource.Body))
	}

	httpReq, err := http.NewRequest(resource.Resource.HTTP.Method, resource.Resource.HTTP.URL, body)
	if err != nil {
		return BrokerResponse{}, "", fmt.Errorf("build request: %w", err)
	}

	// Copy safe guest headers (skip hop-by-hop and auth headers).
	for k, vals := range resource.SanitizedHeaders {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	// Inject host-side credential.
	if binding.IsLoaded() {
		httpReq.Header.Set("Authorization", binding.BearerToken())
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return BrokerResponse{}, "", fmt.Errorf("outbound request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return BrokerResponse{}, "", fmt.Errorf("read response body: %w", err)
	}

	// Build sanitized response headers (no auth material).
	respHeaders := make(map[string][]string)
	for k, vals := range resp.Header {
		if isSensitiveHeader(k) {
			continue
		}
		respHeaders[k] = vals
	}

	return BrokerResponse{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		BodyBase64: base64.StdEncoding.EncodeToString(respBody),
		Allowed:    true,
	}, digestBytes(respBody), nil
}

func (b *Broker) deny(record governance.CapabilityRecord, bindingName string, leaseCheck *lease.Check) BrokerResponse {
	domain := record.Request.Resource
	actionType := record.Request.ActionType
	reason := record.Decision.RuleID
	detail := record.Decision.Reason
	if record.Use.HostAction == nil && record.Request.ActionType != governance.ActionHostRepoApply && !strings.HasPrefix(reason, "broker.host_action_") {
		b.emit(telemetry.KindCredentialDenied, telemetry.CredentialBrokerData{
			ExecutionID:  b.execID,
			BindingName:  bindingName,
			TargetDomain: domain,
			ActionType:   actionType,
			Outcome:      "denied",
			DenialReason: reason,
		})
	}
	if len(record.Decision.AuditPayload) == 0 {
		record.Decision.AuditPayload = map[string]string{
			"resource": domain,
		}
	}
	record.Use.BindingName = bindingName
	record.Use.CredentialsInjected = bindingName != ""
	record.Use.DenialMarker = "governed_action_denied"
	if leaseCheck != nil {
		record.Use.Lease = leaseCheck
	}
	record = b.attachEscalation(record)
	b.emitGovernedAction(record.ToGovernedActionData())
	resp := BrokerResponse{
		Denied:     true,
		DenyReason: reason,
		Error:      detail,
		StatusCode: http.StatusForbidden,
	}
	if escalation.IsTerminalEvidence(record.Use.Escalation) {
		resp.TerminalReason = escalation.TerminationReasonPrivilegeEscalation
	}
	return resp
}

func (b *Broker) denyError(target, actionType, policyDigest, reason, detail string, leaseCheck *lease.Check) BrokerResponse {
	return b.deny(governance.CapabilityRecord{
		Request: governance.Request{
			ExecutionID: b.execID,
			ActionType:  actionType,
			Target:      target,
			Brokered:    true,
		},
		Decision: governance.Decision{
			Deny:         true,
			RuleID:       reason,
			Reason:       detail,
			PolicyDigest: policyDigest,
		},
		Use: governance.CapabilityUse{
			Path: governance.CapabilityPathBroker,
		},
	}, "", leaseCheck)
}

func (b *Broker) emit(kind string, data telemetry.CredentialBrokerData) {
	observability.Info(kind, observability.Fields{
		"execution_id":  data.ExecutionID,
		"binding_name":  data.BindingName,
		"target_domain": data.TargetDomain,
		"method":        data.Method,
		"action_type":   data.ActionType,
		"outcome":       data.Outcome,
		"denial_reason": data.DenialReason,
	})
	if b.bus != nil {
		b.bus.Emit(kind, data)
	}
}

func (b *Broker) emitGovernedAction(data telemetry.GovernedActionData) {
	fields := observability.Fields{
		"execution_id":         data.ExecutionID,
		"action_type":          data.ActionType,
		"target":               data.Target,
		"decision":             data.Decision,
		"outcome":              data.Outcome,
		"rule_id":              data.RuleID,
		"policy_digest":        data.PolicyDigest,
		"brokered":             data.Brokered,
		"brokered_credentials": data.BrokeredCredentials,
	}
	if data.Approval != nil {
		fields["approval_result"] = string(data.Approval.Result)
		fields["approval_reason"] = data.Approval.Reason
		fields["approval_ticket_id"] = data.Approval.TicketID
		fields["resource_digest"] = data.Approval.ResourceDigest
		fields["approval_consumed"] = data.Approval.Consumed
	}
	if data.Lease != nil {
		fields["lease_result"] = string(data.Lease.Result)
		fields["lease_reason"] = data.Lease.Reason
		fields["lease_id"] = data.Lease.LeaseID
		fields["lease_budget_result"] = string(data.Lease.BudgetResult)
		fields["lease_grant_id"] = data.Lease.GrantID
	}
	if data.Escalation != nil {
		values := make([]string, 0, len(data.Escalation.Signals))
		for _, signal := range data.Escalation.Signals {
			values = append(values, string(signal))
		}
		fields["escalation_signals"] = strings.Join(values, ",")
	}
	if data.HostAction != nil {
		fields["host_action_class"] = string(data.HostAction.Class)
		if data.HostAction.RepoApplyPatch != nil {
			fields["repo_label"] = data.HostAction.RepoApplyPatch.RepoLabel
			fields["patch_digest"] = data.HostAction.RepoApplyPatch.PatchDigest
		}
	}
	observability.Info("governed_action", fields)
	if b.bus != nil {
		b.bus.Emit(telemetry.KindGovernedAction, data)
	}
}

func (b *Broker) attachEscalation(record governance.CapabilityRecord) governance.CapabilityRecord {
	if !record.Decision.Deny || b.bus == nil {
		record.Use.Escalation = nil
		return record
	}
	record.Use.Escalation = b.bus.ClassifyEscalation(escalation.Observation{
		ActionType:      record.Request.ActionType,
		CapabilityPath:  string(record.Use.Path),
		Decision:        "deny",
		RuleID:          record.Decision.RuleID,
		Target:          record.Request.Target,
		Resource:        record.Request.Resource,
		HostActionClass: brokerEscalationHostActionClass(record),
	})
	return record
}

func (b *Broker) HandleTerminalResponse(resp BrokerResponse) {
	if b == nil || b.bus == nil {
		return
	}
	if strings.TrimSpace(resp.TerminalReason) == "" {
		return
	}
	b.bus.TriggerTermination(resp.TerminalReason)
}

func brokerEscalationHostActionClass(record governance.CapabilityRecord) string {
	if record.Use.HostAction != nil {
		return string(record.Use.HostAction.Class)
	}
	if record.Decision.AuditPayload != nil {
		return strings.TrimSpace(record.Decision.AuditPayload["host_action_class"])
	}
	return ""
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func extractDomain(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("URL has no host: %q", rawURL)
	}
	// Strip port if present.
	host := parsed.Hostname()
	return strings.ToLower(host), nil
}

func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, blocked := range strings.Split(responseHeaderDenylist, ",") {
		if lower == blocked {
			return true
		}
	}
	return false
}

func decodeRequestBody(raw string) ([]byte, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	return decoded, nil
}

func withApprovalFailure(record governance.CapabilityRecord, check approval.Check, detail string) governance.CapabilityRecord {
	record.Decision.Allow = false
	record.Decision.Deny = true
	record.Decision.RuleID = check.Reason
	record.Decision.Reason = detail
	record.Use.Approval = &check
	record.Decision.AuditPayload = mergeAuditPayload(record.Decision.AuditPayload, map[string]string{
		"approval_result":      string(check.Result),
		"approval_reason":      check.Reason,
		"resource_digest":      check.ResourceDigest,
		"resource_digest_algo": check.ResourceDigestAlgo,
		"approval_consumed":    strconv.FormatBool(check.Consumed),
	})
	return record
}

func withLeaseFailure(record governance.CapabilityRecord, check lease.Check, detail string) governance.CapabilityRecord {
	record.Decision.Allow = false
	record.Decision.Deny = true
	record.Decision.RuleID = check.Reason
	record.Decision.Reason = detail
	record.Use.Lease = &check
	record.Decision.AuditPayload = mergeAuditPayload(record.Decision.AuditPayload, map[string]string{
		"lease_result":         string(check.Result),
		"lease_reason":         check.Reason,
		"lease_id":             check.LeaseID,
		"lease_grant_id":       check.GrantID,
		"selector_digest":      check.SelectorDigest,
		"selector_digest_algo": check.SelectorDigestAlgo,
		"lease_budget_result":  string(check.BudgetResult),
	})
	return record
}

func withHostActionFailure(record governance.CapabilityRecord, approvalCheck *approval.Check, leaseCheck *lease.Check, err error) governance.CapabilityRecord {
	record.Decision.Allow = false
	record.Decision.Deny = true
	record.Decision.Reason = err.Error()
	if typed := (*hostaction.Error)(nil); hostaction.AsError(err, &typed) {
		record.Decision.RuleID = typed.RuleID
		record.Decision.AuditPayload = mergeAuditPayload(record.Decision.AuditPayload, typed.AuditPayload)
	} else {
		record.Decision.RuleID = "broker.host_action_unsupported"
	}
	if approvalCheck != nil {
		record.Use.Approval = approvalCheck
	}
	if leaseCheck != nil {
		record.Use.Lease = leaseCheck
	}
	return record
}

func hostActionActionType(req *hostaction.Request) string {
	if req == nil {
		return ""
	}
	switch req.Class {
	case hostaction.ClassRepoApplyPatchV1:
		return governance.ActionHostRepoApply
	default:
		return ""
	}
}

func (b *Broker) denyHostActionError(req *hostaction.Request, actionType string, err error) BrokerResponse {
	target := ""
	resource := ""
	audit := map[string]string{}
	if req != nil && req.RepoApplyPatch != nil {
		resource = strings.ToLower(strings.TrimSpace(req.RepoApplyPatch.RepoLabel))
		target = "repo:" + resource
		audit["repo_label"] = resource
	}
	record := governance.CapabilityRecord{
		Request: governance.Request{
			ExecutionID: b.execID,
			ActionType:  actionType,
			Target:      target,
			Resource:    resource,
			Brokered:    true,
		},
		Decision: governance.Decision{
			PolicyDigest: b.policyDigest,
			AuditPayload: audit,
		},
		Use: governance.CapabilityUse{
			Path: governance.CapabilityPathBroker,
		},
	}
	return b.deny(withHostActionFailure(record, nil, nil, err), "", nil)
}

func hostActionAuditPayload(evidence *hostaction.Evidence) map[string]string {
	if evidence == nil {
		return nil
	}
	payload := map[string]string{
		"host_action_class": string(evidence.Class),
	}
	if evidence.RepoApplyPatch != nil {
		payload["repo_label"] = evidence.RepoApplyPatch.RepoLabel
		payload["patch_digest"] = evidence.RepoApplyPatch.PatchDigest
		payload["patch_digest_algo"] = evidence.RepoApplyPatch.PatchDigestAlgo
		payload["base_revision"] = evidence.RepoApplyPatch.BaseRevision
		payload["affected_path_count"] = strconv.Itoa(len(evidence.RepoApplyPatch.AffectedPaths))
	}
	return payload
}

func verificationDetail(reason string, err error) string {
	switch reason {
	case "broker.approval_ticket_expired":
		return "approval ticket expired"
	case "broker.approval_ticket_execution_mismatch":
		return "approval ticket execution_id did not match this execution"
	case "broker.approval_ticket_policy_mismatch":
		return "approval ticket policy_digest did not match this execution"
	case "broker.approval_ticket_action_type_mismatch":
		return "approval ticket action_type did not match this request"
	case "broker.approval_ticket_resource_mismatch":
		return "approval ticket resource did not match this request"
	case "broker.approval_ticket_signature_invalid":
		return "approval ticket signature was invalid or used an unknown key"
	case "broker.approval_ticket_malformed":
		return "approval ticket was malformed"
	default:
		if err != nil && strings.TrimSpace(err.Error()) != "" {
			return err.Error()
		}
		return "approval ticket verification failed"
	}
}

func leaseVerificationDetail(reason string, err error) string {
	switch reason {
	case "broker.lease_missing":
		return "execution does not have an active lease"
	case "broker.lease_expired":
		return "lease expired"
	case "broker.lease_execution_mismatch":
		return "lease execution_id did not match this execution"
	case "broker.lease_policy_mismatch":
		return "lease policy_digest did not match this execution"
	case "broker.lease_authority_mismatch":
		return "lease authority_digest did not match this execution"
	case "broker.lease_resource_mismatch":
		return "lease selector did not match this request"
	case "broker.lease_signature_invalid":
		return "lease signature was invalid or used an unknown key"
	case "broker.lease_malformed":
		return "lease was malformed"
	case "broker.lease_action_kind_unsupported":
		return "lease action kind is not supported in v1"
	default:
		if err != nil && strings.TrimSpace(err.Error()) != "" {
			return err.Error()
		}
		return "lease verification failed"
	}
}

func leaseActionKind(actionType string) (lease.ActionKind, bool) {
	switch governance.NormalizeActionType(actionType) {
	case governance.ActionHTTPRequest:
		return lease.ActionKindHTTPRequest, true
	case governance.ActionHostRepoApply:
		return lease.ActionKindHostRepoApplyPatch, true
	default:
		return "", false
	}
}

func mergeAuditPayload(parts ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, part := range parts {
		for key, value := range part {
			if strings.TrimSpace(value) == "" {
				continue
			}
			merged[key] = value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}
