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
				PolicyDigest: governance.DigestBrokerScope(b.scope),
				AuditPayload: map[string]string{"target_domain": domain},
			},
			Use: governance.CapabilityUse{
				Path: governance.CapabilityPathBroker,
			},
		}, "")
	}

	if domainErr != nil {
		return b.denyError(target, actionType, governance.DigestBrokerScope(b.scope), "broker.invalid_url", fmt.Sprintf("invalid URL: %v", domainErr))
	}
	record := governance.EvaluateBrokerCapability(b.scope, governance.Request{
		ExecutionID: b.execID,
		ActionType:  actionType,
		Method:      req.Method,
		Target:      target,
		Resource:    domain,
		Brokered:    true,
	})
	if record.Decision.Deny {
		return b.deny(record, "")
	}

	// Find the first loaded credential binding from allowed delegations.
	binding, bindingName := b.resolveBinding()
	if len(b.scope.AllowedDelegations) > 0 && !binding.IsLoaded() {
		record.Decision.Allow = false
		record.Decision.Deny = true
		record.Decision.RuleID = "broker.binding_unavailable"
		record.Decision.Reason = "no configured host credential matched broker_scope.allowed_delegations"
		record.Use.BindingName = ""
		return b.deny(record, "")
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
		record.Use.BindingName = bindingName
		record.Use.CredentialsInjected = binding.IsLoaded()
		record.Use.Error = err.Error()
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
	record.Use.Used = true
	b.emitGovernedAction(record.ToGovernedActionData())

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

func (b *Broker) deny(record governance.CapabilityRecord, bindingName string) BrokerResponse {
	domain := record.Request.Resource
	actionType := record.Request.ActionType
	reason := record.Decision.RuleID
	detail := record.Decision.Reason
	b.emit(telemetry.KindCredentialDenied, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		BindingName:  bindingName,
		TargetDomain: domain,
		ActionType:   actionType,
		Outcome:      "denied",
		DenialReason: reason,
	})
	if len(record.Decision.AuditPayload) == 0 {
		record.Decision.AuditPayload = map[string]string{
			"target_domain": domain,
		}
	}
	record.Use.BindingName = bindingName
	record.Use.CredentialsInjected = bindingName != ""
	record.Use.DenialMarker = "governed_action_denied"
	b.emitGovernedAction(record.ToGovernedActionData())
	return BrokerResponse{
		Denied:     true,
		DenyReason: reason,
		Error:      detail,
		StatusCode: http.StatusForbidden,
	}
}

func (b *Broker) denyError(target, actionType, policyDigest, reason, detail string) BrokerResponse {
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
	}, "")
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
