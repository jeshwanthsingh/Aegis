package receipt

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNewSignerDevRequiresConfiguredSeed(t *testing.T) {
	_, err := NewSigner(SigningConfig{Mode: SigningModeDev})
	if err == nil {
		t.Fatal("expected explicit dev mode to require a configured seed")
	}
	if !strings.Contains(err.Error(), EnvSigningSeed) || !strings.Contains(err.Error(), "deterministic fallback signing is disabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSignerStrictRequiresConfiguredSeed(t *testing.T) {
	_, err := NewSigner(SigningConfig{Mode: SigningModeStrict})
	if err == nil {
		t.Fatal("expected strict mode error")
	}
	if !strings.Contains(err.Error(), EnvSigningSeed) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSignerStrictRejectsMalformedSeed(t *testing.T) {
	_, err := NewSigner(SigningConfig{Mode: SigningModeStrict, SeedB64: "not-base64"})
	if err == nil {
		t.Fatal("expected malformed seed error")
	}
	if !strings.Contains(err.Error(), "decode receipt signing seed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSignerStrictUsesConfiguredSeed(t *testing.T) {
	seed := sha256.Sum256([]byte("strict-seed"))
	signer, err := NewSigner(SigningConfig{Mode: SigningModeStrict, SeedB64: base64.StdEncoding.EncodeToString(seed[:])})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Mode != SigningModeStrict {
		t.Fatalf("mode = %q", signer.Mode)
	}
	if signer.KeySource != KeySourceConfiguredSeed {
		t.Fatalf("key source = %q", signer.KeySource)
	}
	if signer.KeyID == "" {
		t.Fatal("expected key id")
	}
}

func TestNewSignerFromEnvNoSilentStrictFallback(t *testing.T) {
	t.Setenv(EnvSigningMode, string(SigningModeStrict))
	t.Setenv(EnvSigningSeed, "")
	_, err := NewSignerFromEnv()
	if err == nil {
		t.Fatal("expected strict mode env error")
	}
}

func TestNewSignerFromEnvDefaultsToStrictWithConfiguredSeed(t *testing.T) {
	seed := sha256.Sum256([]byte("default-strict-seed"))
	t.Setenv(EnvSigningMode, "")
	t.Setenv(EnvSigningSeed, base64.StdEncoding.EncodeToString(seed[:]))
	signer, err := NewSignerFromEnv()
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}
	if signer.Mode != SigningModeStrict {
		t.Fatalf("mode = %q", signer.Mode)
	}
	if signer.KeySource != KeySourceConfiguredSeed {
		t.Fatalf("key source = %q", signer.KeySource)
	}
}

func TestNewSignerFromEnvExplicitDevUsesConfiguredSeed(t *testing.T) {
	seed := sha256.Sum256([]byte("explicit-dev-seed"))
	t.Setenv(EnvSigningMode, string(SigningModeDev))
	t.Setenv(EnvSigningSeed, base64.StdEncoding.EncodeToString(seed[:]))
	signer, err := NewSignerFromEnv()
	if err != nil {
		t.Fatalf("NewSignerFromEnv: %v", err)
	}
	if signer.Mode != SigningModeDev {
		t.Fatalf("mode = %q", signer.Mode)
	}
	if signer.KeySource != KeySourceConfiguredSeed {
		t.Fatalf("key source = %q", signer.KeySource)
	}
}

func TestBuildSignedReceiptStrictModeTrustPosture(t *testing.T) {
	seed := sha256.Sum256([]byte("strict-build-seed"))
	signer, err := NewSigner(SigningConfig{Mode: SigningModeStrict, SeedB64: base64.StdEncoding.EncodeToString(seed[:])})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	receipt, err := BuildSignedReceipt(Input{ExecutionID: "exec_strict", Backend: "firecracker", StartedAt: time.Unix(1700000000, 0).UTC(), FinishedAt: time.Unix(1700000001, 0).UTC(), Outcome: Outcome{ExitCode: 0, Reason: "completed", ContainmentVerdict: "completed"}}, signer)
	if err != nil {
		t.Fatalf("BuildSignedReceipt: %v", err)
	}
	if receipt.Statement.Predicate.Trust.SigningMode != SigningModeStrict {
		t.Fatalf("signing mode = %q", receipt.Statement.Predicate.Trust.SigningMode)
	}
	if receipt.Statement.Predicate.Trust.KeySource != KeySourceConfiguredSeed {
		t.Fatalf("key source = %q", receipt.Statement.Predicate.Trust.KeySource)
	}
}
