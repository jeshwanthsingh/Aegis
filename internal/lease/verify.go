package lease

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"aegis/internal/approval"
	"aegis/internal/dsse"
)

type VerificationError struct {
	Result CheckResult
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
		return nil, fmt.Errorf("lease key resolver is not configured")
	}
	publicKey, ok := r.keys[strings.TrimSpace(keyID)]
	if !ok {
		return nil, fmt.Errorf("unknown lease key id %q", keyID)
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

type LeaseVerifier struct {
	resolver KeyResolver
	now      func() time.Time
}

func NewVerifier(resolver KeyResolver) *LeaseVerifier {
	return &LeaseVerifier{
		resolver: resolver,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func VerifierFromIssuer(issuer *LocalIssuer) *LeaseVerifier {
	if issuer == nil {
		return nil
	}
	return NewVerifier(NewStaticKeyResolver(map[string]ed25519.PublicKey{
		issuer.KeyID: issuer.PublicKey,
	}))
}

func (v *LeaseVerifier) Verify(ctx context.Context, signed SignedLease, expected VerificationRequest) (VerifiedLease, error) {
	if v == nil || v.resolver == nil {
		return VerifiedLease{}, &VerificationError{Result: CheckUnavailable, Reason: "broker.lease_unavailable"}
	}
	if signed.Envelope.PayloadType != dsse.PayloadType {
		return VerifiedLease{}, malformedError("unexpected payload type %q", signed.Envelope.PayloadType)
	}
	if len(signed.Envelope.Signatures) == 0 {
		return VerifiedLease{}, malformedError("dsse envelope has no signatures")
	}
	signature := signed.Envelope.Signatures[0]
	payload, err := base64.StdEncoding.DecodeString(signed.Envelope.Payload)
	if err != nil {
		return VerifiedLease{}, malformedError("decode dsse payload: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(signature.Sig)
	if err != nil {
		return VerifiedLease{}, malformedError("decode dsse signature: %v", err)
	}
	publicKey, err := v.resolver.Resolve(ctx, signature.KeyID)
	if err != nil {
		return VerifiedLease{}, &VerificationError{Result: CheckSignatureInvalid, Reason: "broker.lease_signature_invalid", Cause: err}
	}
	if !ed25519.Verify(publicKey, dsse.PAE(signed.Envelope.PayloadType, payload), sig) {
		return VerifiedLease{}, &VerificationError{Result: CheckSignatureInvalid, Reason: "broker.lease_signature_invalid", Cause: fmt.Errorf("dsse signature verification failed")}
	}
	var statement Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return VerifiedLease{}, malformedError("decode lease statement: %v", err)
	}
	if statement.Type != dsse.StatementType {
		return VerifiedLease{}, malformedError("unexpected statement type %q", statement.Type)
	}
	if statement.PredicateType != PredicateType {
		return VerifiedLease{}, malformedError("unexpected predicate type %q", statement.PredicateType)
	}
	if len(statement.Subject) != 0 {
		return VerifiedLease{}, malformedError("leases must not include subjects")
	}
	leasePayload, err := validateLease(statement.Predicate)
	if err != nil {
		return VerifiedLease{}, err
	}
	now := expected.Now.UTC()
	if now.IsZero() {
		now = v.now()
	}
	if now.Before(leasePayload.IssuedAt.UTC()) {
		return VerifiedLease{}, malformedError("lease issued_at is in the future")
	}
	if !now.Before(leasePayload.ExpiresAt.UTC()) {
		return VerifiedLease{}, &VerificationError{Result: CheckExpired, Reason: "broker.lease_expired"}
	}
	if strings.TrimSpace(expected.ExecutionID) != strings.TrimSpace(leasePayload.ExecutionID) {
		return VerifiedLease{}, &VerificationError{Result: CheckExecutionMismatch, Reason: "broker.lease_execution_mismatch"}
	}
	if strings.TrimSpace(expected.PolicyDigest) != strings.TrimSpace(leasePayload.PolicyDigest) {
		return VerifiedLease{}, &VerificationError{Result: CheckPolicyMismatch, Reason: "broker.lease_policy_mismatch"}
	}
	if strings.TrimSpace(expected.AuthorityDigest) != strings.TrimSpace(leasePayload.AuthorityDigest) {
		return VerifiedLease{}, &VerificationError{Result: CheckAuthorityMismatch, Reason: "broker.lease_authority_mismatch"}
	}
	if err := validateExpectedAction(expected.ActionKind); err != nil {
		return VerifiedLease{}, &VerificationError{Result: CheckActionMismatch, Reason: "broker.lease_action_kind_unsupported", Cause: err}
	}
	expectedResource, err := approval.CanonicalizeResource(expected.Resource)
	if err != nil {
		return VerifiedLease{}, malformedError("expected resource invalid: %v", err)
	}
	for _, grant := range leasePayload.Grants {
		if grant.ActionKind != expected.ActionKind {
			continue
		}
		if err := MatchSelector(grant.Selector, expected.ActionKind, expectedResource); err != nil {
			continue
		}
		selectorDigest, selectorDigestAlgo, err := DigestSelector(grant.Selector)
		if err != nil {
			return VerifiedLease{}, malformedError("selector digest invalid: %v", err)
		}
		return VerifiedLease{
			Lease:              leasePayload,
			IssuerKeyID:        signature.KeyID,
			Grant:              grant,
			SelectorDigest:     selectorDigest,
			SelectorDigestAlgo: selectorDigestAlgo,
		}, nil
	}
	return VerifiedLease{}, &VerificationError{Result: CheckResourceMismatch, Reason: "broker.lease_resource_mismatch"}
}

func validateLease(lease Lease) (Lease, error) {
	if strings.TrimSpace(lease.Version) != LeaseVersion {
		return Lease{}, malformedError("unexpected lease version %q", lease.Version)
	}
	if strings.TrimSpace(lease.LeaseID) == "" {
		return Lease{}, malformedError("lease_id is required")
	}
	if strings.TrimSpace(lease.Issuer) == "" {
		return Lease{}, malformedError("issuer is required")
	}
	if lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() {
		return Lease{}, malformedError("issued_at and expires_at are required")
	}
	if !lease.ExpiresAt.After(lease.IssuedAt) {
		return Lease{}, malformedError("expires_at must be after issued_at")
	}
	if strings.TrimSpace(lease.ExecutionID) == "" {
		return Lease{}, malformedError("execution_id is required")
	}
	if strings.TrimSpace(lease.PolicyDigest) == "" {
		return Lease{}, malformedError("policy_digest is required")
	}
	if strings.TrimSpace(lease.AuthorityDigest) == "" {
		return Lease{}, malformedError("authority_digest is required")
	}
	if strings.TrimSpace(lease.Workload.Kind) == "" ||
		strings.TrimSpace(lease.Workload.BootDigest) == "" ||
		strings.TrimSpace(lease.Workload.RootfsImage) == "" {
		return Lease{}, malformedError("workload identity is required")
	}
	if len(lease.Grants) == 0 {
		return Lease{}, malformedError("at least one lease grant is required")
	}
	canonical := lease
	canonical.Issuer = strings.TrimSpace(canonical.Issuer)
	canonical.ExecutionID = strings.TrimSpace(canonical.ExecutionID)
	canonical.PolicyDigest = strings.TrimSpace(canonical.PolicyDigest)
	canonical.AuthorityDigest = strings.TrimSpace(canonical.AuthorityDigest)
	canonical.Workload.Kind = strings.TrimSpace(canonical.Workload.Kind)
	canonical.Workload.BootDigest = strings.TrimSpace(canonical.Workload.BootDigest)
	canonical.Workload.RootfsImage = strings.TrimSpace(canonical.Workload.RootfsImage)
	seenGrantIDs := map[string]struct{}{}
	canonical.Grants = make([]Grant, 0, len(lease.Grants))
	for _, grant := range lease.Grants {
		if strings.TrimSpace(grant.GrantID) == "" {
			return Lease{}, malformedError("grant_id is required")
		}
		if _, ok := seenGrantIDs[grant.GrantID]; ok {
			return Lease{}, malformedError("grant_id %q must be unique", grant.GrantID)
		}
		seenGrantIDs[grant.GrantID] = struct{}{}
		if err := validateExpectedAction(grant.ActionKind); err != nil {
			return Lease{}, malformedError("grant %q action invalid: %v", grant.GrantID, err)
		}
		selector, err := CanonicalizeSelector(grant.Selector)
		if err != nil {
			return Lease{}, malformedError("grant %q selector invalid: %v", grant.GrantID, err)
		}
		if grant.Budget.Kind != BudgetKindCount {
			return Lease{}, malformedError("grant %q budget kind must be %q", grant.GrantID, BudgetKindCount)
		}
		canonical.Grants = append(canonical.Grants, Grant{
			GrantID:    strings.TrimSpace(grant.GrantID),
			ActionKind: grant.ActionKind,
			Selector:   selector,
			Budget: Budget{
				Kind:       BudgetKindCount,
				LimitCount: grant.Budget.LimitCount,
			},
		})
	}
	if lease.TrustLimits != nil {
		required := make([]ActionKind, 0, len(lease.TrustLimits.ApprovalRequiredActionKinds))
		seen := map[ActionKind]struct{}{}
		for _, actionKind := range lease.TrustLimits.ApprovalRequiredActionKinds {
			if err := validateExpectedAction(actionKind); err != nil {
				return Lease{}, malformedError("trust_limitations action invalid: %v", err)
			}
			if _, ok := seen[actionKind]; ok {
				continue
			}
			seen[actionKind] = struct{}{}
			required = append(required, actionKind)
		}
		canonical.TrustLimits = &TrustLimitations{ApprovalRequiredActionKinds: required}
	}
	return canonical, nil
}

func validateExpectedAction(actionKind ActionKind) error {
	switch actionKind {
	case ActionKindHTTPRequest, ActionKindHostRepoApplyPatch:
		return nil
	default:
		return fmt.Errorf("unexpected action kind %q", actionKind)
	}
}

func VerificationFailure(err error) (CheckResult, string, bool) {
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
	return &VerificationError{Result: CheckMalformed, Reason: "broker.lease_malformed", Cause: fmt.Errorf(format, args...)}
}
