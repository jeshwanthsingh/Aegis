package policy

import "testing"

func TestValidateRejectsNegativeTimeout(t *testing.T) {
	t.Parallel()

	if err := Default().Validate("python", 16, -1); err == nil {
		t.Fatal("Validate unexpectedly accepted negative timeout")
	}
}

func TestValidateAllowsDefaultTimeoutSentinel(t *testing.T) {
	t.Parallel()

	if err := Default().Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected default timeout sentinel: %v", err)
	}
}

func TestValidateAllowsDirectWebEgressMode(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeDirectWebEgress

	if err := pol.Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected direct_web_egress: %v", err)
	}
	if pol.Network.Mode != NetworkModeDirectWebEgress {
		t.Fatalf("network mode = %q, want %q", pol.Network.Mode, NetworkModeDirectWebEgress)
	}
}

func TestValidateNormalizesLegacyIsolatedMode(t *testing.T) {
	t.Parallel()

	pol := Default()
	pol.Network.Mode = NetworkModeLegacyIsolated

	if err := pol.Validate("python", 16, 0); err != nil {
		t.Fatalf("Validate rejected legacy isolated mode: %v", err)
	}
	if pol.Network.Mode != NetworkModeDirectWebEgress {
		t.Fatalf("network mode = %q, want %q", pol.Network.Mode, NetworkModeDirectWebEgress)
	}
}
