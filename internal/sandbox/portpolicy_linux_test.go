//go:build linux

package sandbox

import (
	"slices"
	"testing"
)

func TestDerivePortPolicy_Unrestricted(t *testing.T) {
	pp := DerivePortPolicy(Policy{}, true)
	if pp.Mode != "unrestricted" {
		t.Errorf("Mode = %q, want unrestricted", pp.Mode)
	}
	if len(pp.AllowSet) != 0 {
		t.Errorf("AllowSet = %v, want empty for unrestricted", pp.AllowSet)
	}
	if !pp.Enforceable {
		t.Error("unrestricted should always be enforceable")
	}
}

func TestDerivePortPolicy_AllowOnly(t *testing.T) {
	policy := Policy{AllowPorts: []int{443, 80}}
	pp := DerivePortPolicy(policy, true)

	if pp.Mode != "allow_only" {
		t.Errorf("Mode = %q, want allow_only", pp.Mode)
	}
	if !containsPort(pp.AllowSet, 443) || !containsPort(pp.AllowSet, 80) {
		t.Errorf("AllowSet = %v, want [80 443]", pp.AllowSet)
	}
	if !pp.Enforceable {
		t.Error("allow_only on ABI4 should be enforceable")
	}
}

func TestDerivePortPolicy_AllowOnly_NotEnforceableOnABI3(t *testing.T) {
	policy := Policy{AllowPorts: []int{443}}
	pp := DerivePortPolicy(policy, false) // landlockABI4=false

	if pp.Enforceable {
		t.Error("allow_only without ABI4 must not be enforceable")
	}
}

// TestDerivePortPolicy_DenyComplement_AboveThreshold verifies the fail-closed
// behaviour: denying a small number of ports yields a complement larger than
// maxLandlockNetRules, so the policy must be non-enforceable with an empty
// AllowSet. shouldGateNetwork still fires, and RestrictNet with zero rules
// blocks all outbound TCP connections.
func TestDerivePortPolicy_DenyComplement_AboveThreshold(t *testing.T) {
	// 2 denied ports → 65533 allowed ports, always > maxLandlockNetRules (4096).
	policy := Policy{DenyPorts: []int{22, 80}}
	pp := DerivePortPolicy(policy, true)

	if pp.Mode != "deny_complement" {
		t.Errorf("Mode = %q, want deny_complement", pp.Mode)
	}
	if pp.Enforceable {
		t.Error("deny_complement above maxLandlockNetRules must not be enforceable")
	}
	if len(pp.AllowSet) != 0 {
		t.Errorf("AllowSet must be empty when above threshold; got %d entries", len(pp.AllowSet))
	}
}

// TestDerivePortPolicy_DenyComplement_WithinThreshold verifies that when the
// complement is small enough (≤ maxLandlockNetRules), the policy is enforceable
// and AllowSet contains exactly the non-denied ports.
func TestDerivePortPolicy_DenyComplement_WithinThreshold(t *testing.T) {
	// Deny ports 1..61439 so that only 4096 ports (61440–65535) remain.
	const denyCount = 61439
	deny := make([]int, denyCount)
	for i := range deny {
		deny[i] = i + 1
	}
	policy := Policy{DenyPorts: deny}
	pp := DerivePortPolicy(policy, true)

	if pp.Mode != "deny_complement" {
		t.Errorf("Mode = %q, want deny_complement", pp.Mode)
	}
	if !pp.Enforceable {
		t.Error("deny_complement within threshold must be enforceable on ABI4")
	}
	wantLen := 65535 - denyCount
	if len(pp.AllowSet) != wantLen {
		t.Errorf("AllowSet len = %d, want %d", len(pp.AllowSet), wantLen)
	}
	// Denied ports must be absent; a non-denied port must be present.
	if containsPort(pp.AllowSet, 1) {
		t.Error("port 1 (denied) must not be in AllowSet")
	}
	if !containsPort(pp.AllowSet, 65535) {
		t.Error("port 65535 (not denied) must be in AllowSet")
	}
}

func TestDerivePortPolicy_AllowIntersectDeny(t *testing.T) {
	policy := Policy{AllowPorts: []int{443, 80, 22}, DenyPorts: []int{22}}
	pp := DerivePortPolicy(policy, true)

	if pp.Mode != "allow_intersect_deny" {
		t.Errorf("Mode = %q, want allow_intersect_deny", pp.Mode)
	}
	if containsPort(pp.AllowSet, 22) {
		t.Error("port 22 should be excluded (in DenyPorts)")
	}
	if !containsPort(pp.AllowSet, 443) || !containsPort(pp.AllowSet, 80) {
		t.Errorf("AllowSet = %v, should contain 443 and 80", pp.AllowSet)
	}
}

func TestValidatePortRange_ValidPorts(t *testing.T) {
	if err := ValidatePortRange([]int{1, 443, 65535}); err != nil {
		t.Errorf("valid ports returned error: %v", err)
	}
}

func TestValidatePortRange_InvalidPort(t *testing.T) {
	if err := ValidatePortRange([]int{443, 65536}); err == nil {
		t.Error("expected error for port 65536")
	}
	if err := ValidatePortRange([]int{-1}); err == nil {
		t.Error("expected error for port -1")
	}
	// Port 0 is rejected to avoid Landlock's ConnectTCP(0) wildcard
	// behaviour leaking through allow_only mode.
	if err := ValidatePortRange([]int{0}); err == nil {
		t.Error("expected error for port 0 (Landlock wildcard)")
	}
}

func TestDerivePortPolicy_DropsPortZero(t *testing.T) {
	// Port 0 in either list must not survive: in allow_only it would
	// otherwise become ConnectTCP(0), a wildcard that allows every port.
	pp := DerivePortPolicy(Policy{AllowPorts: []int{0, 443}}, true)
	if slices.Contains(pp.AllowSet, 0) {
		t.Errorf("AllowSet leaked port 0: %v", pp.AllowSet)
	}
	if !slices.Contains(pp.AllowSet, 443) {
		t.Errorf("AllowSet should still contain 443; got %v", pp.AllowSet)
	}
}

func containsPort(list []uint16, val int) bool {
	return slices.Contains(list, uint16(val)) //nolint:gosec // test values are valid ports
}
