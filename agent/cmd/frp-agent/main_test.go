package main

import (
	"slices"
	"testing"
)

func TestBaseCapabilitiesIncludeReadOnlyInspection(t *testing.T) {
	capabilities := baseCapabilities()
	for _, capability := range []string{"inspect", "risk.scan", "runtime.collect", "certificate.rotate"} {
		if !slices.Contains(capabilities, capability) {
			t.Fatalf("base capabilities %v do not include %q", capabilities, capability)
		}
	}
	for _, capability := range []string{"service.status", "service.start", "service.stop", "service.restart", "config.apply", "config.rollback", "frp.upgrade"} {
		if slices.Contains(capabilities, capability) {
			t.Fatalf("mutation capability %q must require a platform preflight: %v", capability, capabilities)
		}
	}
}
