package main

import "testing"

func TestNormalizeModeDefaultsToAdminOrNode(t *testing.T) {
	if got := normalizeMode("", false); got != modeNode {
		t.Fatalf("empty mode without admin = %q, want node", got)
	}
	if got := normalizeMode("", true); got != modeAdmin {
		t.Fatalf("empty mode with admin = %q, want admin", got)
	}
}

func TestAdminLocalRuntimeIsOptional(t *testing.T) {
	if shouldRunDataPlane(&Config{Mode: modeAdmin}) {
		t.Fatalf("pure admin should not run data plane")
	}
	if !shouldRunDataPlane(&Config{Mode: modeAdmin, Listens: []string{"127.0.0.1:18080"}}) {
		t.Fatalf("admin with local listener should run data plane")
	}
	if !shouldRunDataPlane(&Config{Mode: modeNode, Listens: []string{":8443"}}) {
		t.Fatalf("node should run data plane")
	}
}

func TestNodeModeDoesNotRunAdmin(t *testing.T) {
	if shouldRunAdmin(modeNode) {
		t.Fatalf("node mode should not run admin server")
	}
	if !shouldRunNodeSync(modeNode) {
		t.Fatalf("node mode should run node sync")
	}
	if !shouldRunAdmin(modeAdmin) {
		t.Fatalf("admin mode should run admin server")
	}
	if shouldRunNodeSync(modeAdmin) {
		t.Fatalf("admin mode should not run node sync")
	}
}
