// nolint
//go:build darwin
// +build darwin

package seatbelt

import (
	"strings"
	"testing"
)

// sandbox_init rejects the unknown operation before it sandboxes anything.
// Should that ever change, allowing Default leaves this process unrestricted.
func TestApplyReportsPolicyError(t *testing.T) {
	err := Apply(Policy{Allow(Default, All), Deny("no-such-operation", All)})
	if err == nil {
		t.Fatal("Apply accepted a policy with an unknown operation")
	}

	// sandbox_init explains a rejected policy in its error buffer.
	if msg := err.Error(); !strings.HasPrefix(msg, "sandbox_init returned -1: ") || strings.HasSuffix(msg, "\n") {
		t.Fatalf("error = %q, want sandbox_init's explanation without a trailing newline", msg)
	}
}

func TestInitError(t *testing.T) {
	tests := []struct {
		detail string
		want   string
	}{
		{detail: "", want: "sandbox_init returned -1"},
		{detail: " \n", want: "sandbox_init returned -1"},
		{detail: "syntax error\n", want: "sandbox_init returned -1: syntax error"},
	}

	for _, tt := range tests {
		if got := initError(-1, tt.detail).Error(); got != tt.want {
			t.Errorf("initError(-1, %q) = %q, want %q", tt.detail, got, tt.want)
		}
	}
}
