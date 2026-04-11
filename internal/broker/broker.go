package broker

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegis/internal/observability"
	"aegis/internal/policy/contract"
	"aegis/internal/telemetry"
)

const (
	ActionTypeHTTP    = "http_request"
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
	// Emit request event regardless of outcome.
	domain, domainErr := extractDomain(req.URL)
	b.emit(telemetry.KindCredentialRequest, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		TargetDomain: domain,
		Method:       req.Method,
		ActionType:   ActionTypeHTTP,
		Outcome:      "pending",
	})

	// Reject CONNECT tunneling: host cannot inject auth headers into opaque TLS streams.
	if strings.ToUpper(req.Method) == http.MethodConnect {
		return b.deny(domain, "", "broker.connect_not_supported", "CONNECT tunneling is not supported in v1; use plain HTTP requests")
	}

	if domainErr != nil {
		return b.denyError("broker.invalid_url", fmt.Sprintf("invalid URL: %v", domainErr))
	}

	// Policy check: domain allowlist.
	if !b.domainAllowed(domain) {
		return b.deny(domain, "", "broker.domain_denied", fmt.Sprintf("domain %q is not in broker_scope.allowed_domains", domain))
	}

	// Find the first loaded credential binding from allowed delegations.
	binding, bindingName := b.resolveBinding()
	if len(b.scope.AllowedDelegations) > 0 && !binding.IsLoaded() {
		return b.deny(domain, "", "broker.binding_unavailable", "no configured host credential matched broker_scope.allowed_delegations")
	}

	// Perform the outbound HTTP request with credential injection.
	resp, err := b.execute(req, binding)
	if err != nil {
		b.emit(telemetry.KindCredentialError, telemetry.CredentialBrokerData{
			ExecutionID:  b.execID,
			BindingName:  bindingName,
			TargetDomain: domain,
			Method:       req.Method,
			ActionType:   ActionTypeHTTP,
			Outcome:      "error",
			DenialReason: err.Error(),
		})
		return BrokerResponse{Error: fmt.Sprintf("broker request failed: %v", err)}
	}

	b.emit(telemetry.KindCredentialAllowed, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		BindingName:  bindingName,
		TargetDomain: domain,
		Method:       req.Method,
		ActionType:   ActionTypeHTTP,
		Outcome:      "allowed",
	})

	return resp
}

// AllowedDomains returns the configured allowed domains for external use (e.g. divergence tracking).
func (b *Broker) AllowedDomains() []string {
	return b.scope.AllowedDomains
}

// domainAllowed reports whether the given domain (already lowercased, no port) is allowed.
// Allowed entries may be exact hostnames, host:port pairs, or wildcard prefixes (*.example.com).
func (b *Broker) domainAllowed(domain string) bool {
	if len(b.scope.AllowedDomains) == 0 {
		return false
	}
	for _, allowed := range b.scope.AllowedDomains {
		allowed = strings.TrimSpace(strings.ToLower(allowed))
		if allowed == "" {
			continue
		}
		// Support wildcard prefix: "*.example.com" matches "api.example.com".
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(strings.ToLower(domain), suffix) {
				return true
			}
		} else {
			// Strip port from allowed entry for comparison.
			allowedHost := allowed
			if idx := strings.LastIndex(allowed, ":"); idx >= 0 {
				allowedHost = allowed[:idx]
			}
			if strings.ToLower(domain) == allowedHost || allowed == strings.ToLower(domain) {
				return true
			}
		}
	}
	return false
}

func (b *Broker) resolveBinding() (CredentialBinding, string) {
	for _, name := range b.scope.AllowedDelegations {
		if binding, ok := LoadBinding(name); ok {
			return binding, name
		}
	}
	return CredentialBinding{}, ""
}

func (b *Broker) execute(req BrokerRequest, binding CredentialBinding) (BrokerResponse, error) {
	var body io.Reader
	if req.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err != nil {
			return BrokerResponse{}, fmt.Errorf("decode body: %w", err)
		}
		body = strings.NewReader(string(decoded))
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return BrokerResponse{}, fmt.Errorf("build request: %w", err)
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
		return BrokerResponse{}, fmt.Errorf("outbound request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return BrokerResponse{}, fmt.Errorf("read response body: %w", err)
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
	}, nil
}

func (b *Broker) deny(domain, bindingName, reason, detail string) BrokerResponse {
	b.emit(telemetry.KindCredentialDenied, telemetry.CredentialBrokerData{
		ExecutionID:  b.execID,
		BindingName:  bindingName,
		TargetDomain: domain,
		ActionType:   ActionTypeHTTP,
		Outcome:      "denied",
		DenialReason: reason,
	})
	return BrokerResponse{
		Denied:     true,
		DenyReason: reason,
		Error:      detail,
		StatusCode: http.StatusForbidden,
	}
}

func (b *Broker) denyError(reason, detail string) BrokerResponse {
	return b.deny("", "", reason, detail)
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
