package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegis/internal/governance"
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
	scope  contract.BrokerScope
	execID string
	bus    *telemetry.Bus
	client *http.Client
}

// New constructs a Broker for a single execution.
func New(scope contract.BrokerScope, execID string, bus *telemetry.Bus) *Broker {
	return &Broker{
		scope:  scope,
		execID: execID,
		bus:    bus,
		client: &http.Client{Timeout: brokerHTTPTimeout},
	}
}

// Handle validates a BrokerRequest and, if allowed, performs the outbound HTTP request
// with host-side credential injection. The raw credential value is never returned to the guest.
func (b *Broker) Handle(req BrokerRequest) BrokerResponse {
	actionType := governance.NormalizeActionType(req.ActionType)
	if actionType == "" {
		actionType = governance.ActionHTTPRequest
	}
	target := governance.SanitizeTarget(req.URL)
	policyDigest := governance.DigestBrokerScope(b.scope)

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
		return b.deny(domain, "", target, actionType, "broker.connect_not_supported", "CONNECT tunneling is not supported in v1; use plain HTTP requests", policyDigest, nil)
	}

	if domainErr != nil {
		return b.denyError(target, actionType, policyDigest, "broker.invalid_url", fmt.Sprintf("invalid URL: %v", domainErr))
	}
	decision := governance.EvaluateBroker(b.scope, governance.Request{
		ExecutionID: b.execID,
		ActionType:  actionType,
		Method:      req.Method,
		Target:      target,
		Resource:    domain,
		Brokered:    true,
	})
	if decision.Deny {
		return b.deny(domain, "", target, actionType, decision.RuleID, decision.Reason, decision.PolicyDigest, decision.AuditPayload)
	}

	// Find the first loaded credential binding from allowed delegations.
	binding, bindingName := b.resolveBinding()
	if len(b.scope.AllowedDelegations) > 0 && !binding.IsLoaded() {
		return b.deny(domain, "", target, actionType, "broker.binding_unavailable", "no configured host credential matched broker_scope.allowed_delegations", policyDigest, nil)
	}

	// Perform the outbound HTTP request with credential injection.
	resp, responseDigest, err := b.execute(req, binding)
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
		b.emitGovernedAction(telemetry.GovernedActionData{
			ExecutionID:         b.execID,
			ActionType:          actionType,
			Target:              target,
			Resource:            domain,
			Method:              strings.ToUpper(req.Method),
			Decision:            "allow",
			Outcome:             "error",
			Reason:              "governed action allowed but upstream execution failed",
			RuleID:              "governance.allow",
			PolicyDigest:        policyDigest,
			Brokered:            true,
			BrokeredCredentials: binding.IsLoaded(),
			BindingName:         bindingName,
			Error:               err.Error(),
			AuditPayload: map[string]string{
				"target_domain": domain,
			},
		})
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
	b.emitGovernedAction(telemetry.GovernedActionData{
		ExecutionID:         b.execID,
		ActionType:          actionType,
		Target:              target,
		Resource:            domain,
		Method:              strings.ToUpper(req.Method),
		Decision:            "allow",
		Outcome:             "completed",
		Reason:              "governed action allowed by broker scope",
		RuleID:              "governance.allow",
		PolicyDigest:        policyDigest,
		Brokered:            true,
		BrokeredCredentials: binding.IsLoaded(),
		BindingName:         bindingName,
		ResponseDigest:      responseDigest,
		ResponseDigestAlgo:  "sha256",
		AuditPayload: map[string]string{
			"target_domain": domain,
		},
	})

	return resp
}

// AllowedDomains returns the configured allowed domains for external use (e.g. divergence tracking).
func (b *Broker) AllowedDomains() []string {
	return b.scope.AllowedDomains
}

func (b *Broker) resolveBinding() (CredentialBinding, string) {
	for _, name := range b.scope.AllowedDelegations {
		if binding, ok := LoadBinding(name); ok {
			return binding, name
		}
	}
	return CredentialBinding{}, ""
}

func (b *Broker) execute(req BrokerRequest, binding CredentialBinding) (BrokerResponse, string, error) {
	var body io.Reader
	if req.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err != nil {
			return BrokerResponse{}, "", fmt.Errorf("decode body: %w", err)
		}
		body = strings.NewReader(string(decoded))
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return BrokerResponse{}, "", fmt.Errorf("build request: %w", err)
	}

	// Copy safe guest headers (skip hop-by-hop and auth headers).
	for k, vals := range req.Headers {
		if isSensitiveHeader(k) {
			continue
		}
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

func (b *Broker) deny(domain, bindingName, target, actionType, reason, detail, policyDigest string, auditPayload map[string]string) BrokerResponse {
	b.emit(telemetry.KindCredentialDenied, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		BindingName:  bindingName,
		TargetDomain: domain,
		ActionType:   actionType,
		Outcome:      "denied",
		DenialReason: reason,
	})
	if len(auditPayload) == 0 {
		auditPayload = map[string]string{
			"target_domain": domain,
		}
	}
	b.emitGovernedAction(telemetry.GovernedActionData{
		ExecutionID:         b.execID,
		ActionType:          actionType,
		Target:              target,
		Resource:            domain,
		Decision:            "deny",
		Outcome:             "denied",
		Reason:              detail,
		RuleID:              reason,
		PolicyDigest:        policyDigest,
		Brokered:            true,
		BrokeredCredentials: bindingName != "",
		BindingName:         bindingName,
		DenialMarker:        "governed_action_denied",
		AuditPayload:        auditPayload,
	})
	return BrokerResponse{
		Denied:     true,
		DenyReason: reason,
		Error:      detail,
		StatusCode: http.StatusForbidden,
	}
}

func (b *Broker) denyError(target, actionType, policyDigest, reason, detail string) BrokerResponse {
	return b.deny("", "", target, actionType, reason, detail, policyDigest, nil)
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
	observability.Info("governed_action", observability.Fields{
		"execution_id":         data.ExecutionID,
		"action_type":          data.ActionType,
		"target":               data.Target,
		"decision":             data.Decision,
		"outcome":              data.Outcome,
		"rule_id":              data.RuleID,
		"policy_digest":        data.PolicyDigest,
		"brokered":             data.Brokered,
		"brokered_credentials": data.BrokeredCredentials,
	})
	if b.bus != nil {
		b.bus.Emit(telemetry.KindGovernedAction, data)
	}
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
