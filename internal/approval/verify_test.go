package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"aegis/internal/dsse"
)

func TestVerifierAcceptsValidTicket(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
	resource, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method:  "POST",
		URL:     "https://api.example.com/v1/items?kind=note",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest: %v", err)
	}
	ticket, err := SignTicket(Ticket{
		Version:      TicketVersion,
		TicketID:     "ticket-1",
		IssuedAt:     time.Unix(100, 0).UTC(),
		ExpiresAt:    time.Unix(200, 0).UTC(),
		Nonce:        "nonce-1",
		ExecutionID:  "exec-1",
		PolicyDigest: "policy-1",
		ActionType:   "http_request",
		Resource:     resource.Resource,
	}, privateKey)
	if err != nil {
		t.Fatalf("SignTicket: %v", err)
	}
	verifier := NewVerifier(NewStaticKeyResolver(map[string]ed25519.PublicKey{
		dsse.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey)): privateKey.Public().(ed25519.PublicKey),
	}))
	verified, err := verifier.Verify(context.Background(), ticket, VerificationRequest{
		ExecutionID:  "exec-1",
		PolicyDigest: "policy-1",
		ActionType:   "http_request",
		Resource:     resource.Resource,
		Now:          time.Unix(150, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Ticket.TicketID != "ticket-1" {
		t.Fatalf("ticket id = %q", verified.Ticket.TicketID)
	}
	if verified.ResourceDigest != resource.ResourceDigest {
		t.Fatalf("resource digest = %q, want %q", verified.ResourceDigest, resource.ResourceDigest)
	}
}

func TestVerifierRejectsResourceMismatch(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	resource, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method:  "GET",
		URL:     "https://api.example.com/v1/items",
		Headers: map[string][]string{},
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest(resource): %v", err)
	}
	ticket, err := SignTicket(Ticket{
		Version:      TicketVersion,
		TicketID:     "ticket-2",
		IssuedAt:     time.Unix(100, 0).UTC(),
		ExpiresAt:    time.Unix(200, 0).UTC(),
		Nonce:        "nonce-2",
		ExecutionID:  "exec-2",
		PolicyDigest: "policy-2",
		ActionType:   "http_request",
		Resource:     resource.Resource,
	}, privateKey)
	if err != nil {
		t.Fatalf("SignTicket: %v", err)
	}
	verifier := NewVerifier(NewStaticKeyResolver(map[string]ed25519.PublicKey{
		dsse.KeyIDFromPublicKey(privateKey.Public().(ed25519.PublicKey)): privateKey.Public().(ed25519.PublicKey),
	}))
	other, err := CanonicalizeHTTPRequest(HTTPRequestInput{
		Method:  "GET",
		URL:     "https://api.example.com/v1/items?other=true",
		Headers: map[string][]string{},
	})
	if err != nil {
		t.Fatalf("CanonicalizeHTTPRequest(other): %v", err)
	}
	_, err = verifier.Verify(context.Background(), ticket, VerificationRequest{
		ExecutionID:  "exec-2",
		PolicyDigest: "policy-2",
		ActionType:   "http_request",
		Resource:     other.Resource,
		Now:          time.Unix(150, 0).UTC(),
	})
	result, reason, ok := VerificationFailure(err)
	if !ok {
		t.Fatalf("VerificationFailure(ok=false): %v", err)
	}
	if result != VerificationResourceMismatch || reason != "broker.approval_ticket_resource_mismatch" {
		t.Fatalf("verification failure = %s %s", result, reason)
	}
}

func TestEncodeTicketHeaderValueRoundTrip(t *testing.T) {
	ticket := SignedTicket{
		Envelope: dsse.Envelope{
			PayloadType: dsse.PayloadType,
			Payload:     base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`)),
			Signatures:  []dsse.Signature{{KeyID: "ed25519:test", Sig: base64.StdEncoding.EncodeToString([]byte("sig"))}},
		},
		Statement: Statement{Type: dsse.StatementType, PredicateType: TicketPredicateType},
	}
	headerValue, err := EncodeTicketHeaderValue(ticket)
	if err != nil {
		t.Fatalf("EncodeTicketHeaderValue: %v", err)
	}
	decoded, err := DecodeTicketHeaderValue(headerValue)
	if err != nil {
		t.Fatalf("DecodeTicketHeaderValue: %v", err)
	}
	if decoded.Envelope.Payload != ticket.Envelope.Payload || decoded.Statement.PredicateType != ticket.Statement.PredicateType {
		t.Fatalf("decoded ticket = %+v", decoded)
	}
}

func TestNewEnvKeyResolverRequiresExplicitPublicKeys(t *testing.T) {
	seed := []byte("01234567890123456789012345678901")
	t.Setenv(EnvPublicKeysJSON, "")
	t.Setenv(EnvSigningSeed, base64.StdEncoding.EncodeToString(seed))

	_, err := NewEnvKeyResolver()
	if err == nil {
		t.Fatal("expected explicit runtime resolver failure")
	}
	if !strings.Contains(err.Error(), EnvPublicKeysJSON) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewEnvInspectKeyResolverFallsBackToSigningSeed(t *testing.T) {
	seed := []byte("01234567890123456789012345678901")
	issuer, err := NewLocalIssuerFromSeed(seed)
	if err != nil {
		t.Fatalf("NewLocalIssuerFromSeed: %v", err)
	}
	t.Setenv(EnvPublicKeysJSON, "")
	t.Setenv(EnvSigningSeed, base64.StdEncoding.EncodeToString(seed))

	resolver, err := NewEnvInspectKeyResolver()
	if err != nil {
		t.Fatalf("NewEnvInspectKeyResolver: %v", err)
	}
	publicKey, err := resolver.Resolve(context.Background(), issuer.KeyID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(publicKey, issuer.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}
