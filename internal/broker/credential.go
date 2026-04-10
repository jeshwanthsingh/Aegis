package broker

import (
	"fmt"
	"os"
	"strings"
)

// CredentialBinding maps a logical name to a host-side secret loaded from env.
// The guest never receives the raw credential value.
type CredentialBinding struct {
	Name  string
	value string // never sent to guest
}

// envVarName returns the env var name for a logical binding: AEGIS_CRED_<NAME>_TOKEN.
func envVarName(name string) string {
	return fmt.Sprintf("AEGIS_CRED_%s_TOKEN", strings.ToUpper(strings.ReplaceAll(name, "-", "_")))
}

// LoadBinding loads a single named credential binding from the environment.
// Returns false if the env var is unset or empty.
func LoadBinding(name string) (CredentialBinding, bool) {
	v := strings.TrimSpace(os.Getenv(envVarName(name)))
	if v == "" {
		return CredentialBinding{}, false
	}
	return CredentialBinding{Name: name, value: v}, true
}

// BearerToken returns the Authorization header value for this binding.
// Returns empty string if the binding has no value.
func (b CredentialBinding) BearerToken() string {
	if b.value == "" {
		return ""
	}
	return "Bearer " + b.value
}

// IsLoaded reports whether this binding has a non-empty credential value.
func (b CredentialBinding) IsLoaded() bool {
	return b.value != ""
}
