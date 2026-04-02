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
