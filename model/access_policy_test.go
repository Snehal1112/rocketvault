package model

import "testing"

// TestValidatePolicyOperation_AcceptsWrapAndUnwrap pins B79: an explicit deny
// on wrap or unwrap must be expressible, so both are valid operations.
func TestValidatePolicyOperation_AcceptsWrapAndUnwrap(t *testing.T) {
	for _, op := range []string{"wrap", "unwrap", "encrypt", "decrypt", "backup"} {
		if err := ValidatePolicyOperation(op); err != nil {
			t.Fatalf("ValidatePolicyOperation(%q) = %v, want nil", op, err)
		}
	}
	if OpWrap != "wrap" || OpUnwrap != "unwrap" {
		t.Fatalf("OpWrap=%q OpUnwrap=%q, want wrap and unwrap", OpWrap, OpUnwrap)
	}
}

// TestValidatePolicyOperation_RejectsUnknown pins that adding wrap and unwrap
// did not widen validation to arbitrary strings.
func TestValidatePolicyOperation_RejectsUnknown(t *testing.T) {
	for _, op := range []string{"", "export", "wrapkey", "Wrap", "unwrap "} {
		if err := ValidatePolicyOperation(op); err == nil {
			t.Fatalf("ValidatePolicyOperation(%q) = nil, want an error", op)
		}
	}
}
