package approval

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"aegis/internal/dsse"
)

type VerificationError struct {
	Result VerificationResult
	Reason string
	Cause  error
}

func (e *VerificationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return e.Reason
}

func (e *VerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type StaticKeyResolver struct {
	keys map[string]ed25519.PublicKey
}

func NewStaticKeyResolver(keys map[string]ed25519.PublicKey) *StaticKeyResolver {
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		cloned[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return &StaticKeyResolver{keys: cloned}
}

func (r *StaticKeyResolver) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	if r == nil {
		return nil, fmt.Errorf("approval key resolver is not configured")
	}
	publicKey, ok := r.keys[strings.TrimSpace(keyID)]
	if !ok {
		return nil, fmt.Errorf("unknown approval key id %q", keyID)
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func ParsePublicKeysJSON(raw string) (*StaticKeyResolver, error) {
	if strings.TrimSpace(raw) == "" {
		return NewStaticKeyResolver(map[string]ed25519.PublicKey{}), nil
	}
	var encoded map[string]string
	if err := json.Unmarshal([]byte(raw), &encoded); err != nil {
		return nil, fmt.Errorf("decode approval public keys json: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for keyID, value := range encoded {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("decode approval public key %q: %w", keyID, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approval public key %q must be %d bytes", keyID, ed25519.PublicKeySize)
		}
		keys[strings.TrimSpace(keyID)] = ed25519.PublicKey(decoded)
	}
	return NewStaticKeyResolver(keys), nil
}

func NewEnvKeyResolver() (*StaticKeyResolver, error) {
	raw := strings.TrimSpace(os.Getenv(EnvPublicKeysJSON))
	if raw == "" {
		return nil, fmt.Errorf("%s is required for runtime approval verification", EnvPublicKeysJSON)
	}
	return ParsePublicKeysJSON(raw)
}

func NewEnvInspectKeyResolver() (*StaticKeyResolver, error) {
	if raw := strings.TrimSpace(os.Getenv(EnvPublicKeysJSON)); raw != "" {
		return ParsePublicKeysJSON(raw)
	}
	issuer, err := NewLocalIssuerFromEnv()
	if err != nil {
		return nil, fmt.Errorf("approval inspect requires %s or %s", EnvPublicKeysJSON, EnvSigningSeed)
	}
	return NewStaticKeyResolver(map[string]ed25519.PublicKey{
		issuer.KeyID: append(ed25519.PublicKey(nil), issuer.PublicKey...),
	}), nil
}

type TicketVerifier struct {
	resolver KeyResolver
	now      func() time.Time
}

func NewVerifier(resolver KeyResolver) *TicketVerifier {
	return &TicketVerifier{
		resolver: resolver,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (v *TicketVerifier) Inspect(ctx context.Context, ticket SignedTicket) (VerifiedTicket, error) {
	if v == nil || v.resolver == nil {
		return VerifiedTicket{}, &VerificationError{Result: VerificationUnavailable, Reason: "broker.approval_ticket_unavailable"}
	}
	if ticket.Envelope.PayloadType != dsse.PayloadType {
		return VerifiedTicket{}, malformedError("unexpected payload type %q", ticket.Envelope.PayloadType)
	}
	if len(ticket.Envelope.Signatures) == 0 {
		return VerifiedTicket{}, malformedError("dsse envelope has no signatures")
	}
	signature := ticket.Envelope.Signatures[0]
	payload, err := base64.StdEncoding.DecodeString(ticket.Envelope.Payload)
	if err != nil {
		return VerifiedTicket{}, malformedError("decode dsse payload: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Sig)
	if err != nil {
		return VerifiedTicket{}, malformedError("decode dsse signature: %v", err)
	}
	publicKey, err := v.resolver.Resolve(ctx, signature.KeyID)
	if err != nil {
		return VerifiedTicket{}, &VerificationError{Result: VerificationSignatureInvalid, Reason: "broker.approval_ticket_signature_invalid", Cause: err}
	}
	if !ed25519.Verify(publicKey, dsse.PAE(ticket.Envelope.PayloadType, payload), sig) {
		return VerifiedTicket{}, &VerificationError{Result: VerificationSignatureInvalid, Reason: "broker.approval_ticket_signature_invalid", Cause: fmt.Errorf("dsse signature verification failed")}
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return VerifiedTicket{}, malformedError("decode approval ticket statement: %v", err)
	}
	if statement.Type != dsse.StatementType {
		return VerifiedTicket{}, malformedError("unexpected statement type %q", statement.Type)
	}
	if statement.PredicateType != TicketPredicateType {
		return VerifiedTicket{}, malformedError("unexpected predicate type %q", statement.PredicateType)
	}
	if len(statement.Subject) != 0 {
		return VerifiedTicket{}, malformedError("approval tickets must not include subjects")
	}
	ticketPayload, resourceDigest, resourceDigestAlgo, err := validateTicket(statement.Predicate)
	if err != nil {
		return VerifiedTicket{}, err
	}
	return VerifiedTicket{
		Ticket:             ticketPayload,
		IssuerKeyID:        signature.KeyID,
		ResourceDigest:     resourceDigest,
		ResourceDigestAlgo: resourceDigestAlgo,
	}, nil
}

func (v *TicketVerifier) Verify(ctx context.Context, ticket SignedTicket, expected VerificationRequest) (VerifiedTicket, error) {
	verified, err := v.Inspect(ctx, ticket)
	if err != nil {
		return VerifiedTicket{}, err
	}
	now := expected.Now.UTC()
	if now.IsZero() {
		now = v.now()
	}
	if now.Before(verified.Ticket.IssuedAt.UTC()) {
		return VerifiedTicket{}, malformedError("ticket issued_at is in the future")
	}
	if !now.Before(verified.Ticket.ExpiresAt.UTC()) {
		return VerifiedTicket{}, &VerificationError{Result: VerificationExpired, Reason: "broker.approval_ticket_expired"}
	}
	if strings.TrimSpace(expected.ExecutionID) != strings.TrimSpace(verified.Ticket.ExecutionID) {
		return VerifiedTicket{}, &VerificationError{Result: VerificationExecutionMismatch, Reason: "broker.approval_ticket_execution_mismatch"}
	}
	if strings.TrimSpace(expected.PolicyDigest) != strings.TrimSpace(verified.Ticket.PolicyDigest) {
		return VerifiedTicket{}, &VerificationError{Result: VerificationPolicyMismatch, Reason: "broker.approval_ticket_policy_mismatch"}
	}
	if strings.TrimSpace(expected.ActionType) != strings.TrimSpace(verified.Ticket.ActionType) {
		return VerifiedTicket{}, &VerificationError{Result: VerificationActionTypeMismatch, Reason: "broker.approval_ticket_action_type_mismatch"}
	}
	expectedDigest, _, err := DigestResource(expected.Resource)
	if err != nil {
		return VerifiedTicket{}, malformedError("expected approval resource is invalid: %v", err)
	}
	if expectedDigest != verified.ResourceDigest {
		return VerifiedTicket{}, &VerificationError{Result: VerificationResourceMismatch, Reason: "broker.approval_ticket_resource_mismatch"}
	}
	return verified, nil
}

func validateTicket(ticket Ticket) (Ticket, string, string, error) {
	if strings.TrimSpace(ticket.Version) != TicketVersion {
		return Ticket{}, "", "", malformedError("unexpected ticket version %q", ticket.Version)
	}
	if strings.TrimSpace(ticket.TicketID) == "" {
		return Ticket{}, "", "", malformedError("ticket_id is required")
	}
	if strings.TrimSpace(ticket.Nonce) == "" {
		return Ticket{}, "", "", malformedError("nonce is required")
	}
	if strings.TrimSpace(ticket.ExecutionID) == "" {
		return Ticket{}, "", "", malformedError("execution_id is required")
	}
	if strings.TrimSpace(ticket.PolicyDigest) == "" {
		return Ticket{}, "", "", malformedError("policy_digest is required")
	}
	if strings.TrimSpace(ticket.ActionType) == "" {
		return Ticket{}, "", "", malformedError("action_type is required")
	}
	if ticket.IssuedAt.IsZero() || ticket.ExpiresAt.IsZero() {
		return Ticket{}, "", "", malformedError("issued_at and expires_at are required")
	}
	resource, err := CanonicalizeResource(ticket.Resource)
	if err != nil {
		return Ticket{}, "", "", malformedError("resource invalid: %v", err)
	}
	resourceDigest, resourceDigestAlgo, err := DigestResource(resource)
	if err != nil {
		return Ticket{}, "", "", malformedError("resource digest invalid: %v", err)
	}
	return Ticket{
		Version:      TicketVersion,
		TicketID:     strings.TrimSpace(ticket.TicketID),
		IssuedAt:     ticket.IssuedAt.UTC(),
		ExpiresAt:    ticket.ExpiresAt.UTC(),
		Nonce:        strings.TrimSpace(ticket.Nonce),
		ExecutionID:  strings.TrimSpace(ticket.ExecutionID),
		PolicyDigest: strings.TrimSpace(ticket.PolicyDigest),
		ActionType:   strings.TrimSpace(ticket.ActionType),
		Resource:     resource,
	}, resourceDigest, resourceDigestAlgo, nil
}

func VerificationFailure(err error) (VerificationResult, string, bool) {
	var typed *VerificationError
	if typed == nil && err == nil {
		return "", "", false
	}
	if !AsVerificationError(err, &typed) {
		return "", "", false
	}
	return typed.Result, typed.Reason, true
}

func AsVerificationError(err error, target **VerificationError) bool {
	return err != nil && target != nil && errors.As(err, target)
}

func malformedError(format string, args ...any) error {
	return &VerificationError{Result: VerificationMalformed, Reason: "broker.approval_ticket_malformed", Cause: fmt.Errorf(format, args...)}
}
