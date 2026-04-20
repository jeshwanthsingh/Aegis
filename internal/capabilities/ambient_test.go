//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestRaiseAmbientRejectsUnknownCapability(t *testing.T) {
	if err := RaiseAmbient([]string{"cap_fake"}); err == nil {
		t.Fatal("expected unknown capability error")
	}
}

func TestRaiseAmbientSupportedCaps(t *testing.T) {
	hasCap, err := hasPermittedCapability("cap_net_admin")
	if err != nil {
		t.Fatalf("hasPermittedCapability(cap_net_admin): %v", err)
	}
	if !hasCap {
		t.Skip("requires cap_net_admin in permitted set")
	}
	if err := RaiseAmbient([]string{"cap_net_admin"}); err != nil {
		t.Fatalf("RaiseAmbient: %v", err)
	}
	amb, err := readCapabilitySetHex("CapAmb")
	if err != nil {
		t.Fatalf("readCapabilitySetHex(CapAmb): %v", err)
	}
	const capNetAdminBit uint64 = 1 << 12
	if amb&capNetAdminBit == 0 {
		t.Fatalf("CapAmb = %#x, want bit %#x set", amb, capNetAdminBit)
	}
}

func hasPermittedCapability(capName string) (bool, error) {
	capNum, err := capabilityNumber(capName)
	if err != nil {
		return false, err
	}
	value, err := readCapabilitySetHex("CapPrm")
	if err != nil {
		return false, err
	}
	return value&(uint64(1)<<uint(capNum)) != 0, nil
}

func readCapabilitySetHex(name string) (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	prefix := name + ":"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		value, err := strconv.ParseUint(raw, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s %q: %w", name, raw, err)
		}
		return value, nil
	}
	return 0, fmt.Errorf("%s not found in /proc/self/status", name)
}
