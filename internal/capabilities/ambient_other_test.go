//go:build !linux

package capabilities

import "testing"

func TestRaiseAmbientNoopOnNonLinux(t *testing.T) {
	if err := RaiseAmbient([]string{"cap_net_admin"}); err != nil {
		t.Fatalf("RaiseAmbient: %v", err)
	}
}
