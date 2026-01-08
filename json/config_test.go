//go:build (linux || darwin || windows) && (amd64 || arm64)

package json

import (
	"testing"

	"github.com/bytedance/sonic"
)

func TestSetConfigUpdatesAPI(t *testing.T) {
	t.Cleanup(func() {
		SetConfig(&sonic.Config{
			EscapeHTML:       true,
			SortMapKeys:      true,
			CompactMarshaler: true,
			CopyString:       true,
			ValidateString:   true,
		})
	})

	payload := map[string]string{"value": "<tag>"}

	baseline, err := Marshal(payload)
	if err != nil {
		t.Fatalf("marshal with default config returned error: %v", err)
	}
	const escaped = "{\"value\":\"\\u003ctag\\u003e\"}"
	if string(baseline) != escaped {
		t.Fatalf("marshal with default config = %q, want %q", string(baseline), escaped)
	}

	SetConfig(&sonic.Config{
		EscapeHTML:       false,
		SortMapKeys:      true,
		CompactMarshaler: true,
		CopyString:       true,
		ValidateString:   true,
	})

	updated, err := Marshal(payload)
	if err != nil {
		t.Fatalf("marshal after SetConfig returned error: %v", err)
	}
	const unescaped = "{\"value\":\"<tag>\"}"
	if string(updated) != unescaped {
		t.Fatalf("marshal after SetConfig = %q, want %q", string(updated), unescaped)
	}
}
