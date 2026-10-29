//go:build darwin
// +build darwin

package seatbelt

import "testing"

func TestPolicyString(t *testing.T) {
	policy := Policy{
		Allow(Default, All),
		Deny(FileRead, All),
		Allow(FileReadData, Literal("/")),
		Allow(FileWrite, Subpath("/private/tmp")),
		Allow(NetworkInbound, LocalTCP(8443)),
		Allow(NetworkOutbound, RemoteTCP(443)),
	}

	want := `(version 1)
(allow default)
(deny file-read*)
(allow file-read-data (literal "/"))
(allow file-write* (subpath "/private/tmp"))
(allow network-inbound (local tcp "*:8443"))
(allow network-outbound (remote tcp "*:443"))`
	if got := policy.String(); got != want {
		t.Fatalf("String() =\n%s\nwant:\n%s", got, want)
	}

	if got := (Policy{}).String(); got != "(version 1)" {
		t.Fatalf("empty policy String() = %q, want %q", got, "(version 1)")
	}
}

// Paths can come from symlink targets on disk, so a crafted name must stay
// inside its string rather than add rules of its own.
func TestFilterQuotesValue(t *testing.T) {
	tests := []struct {
		filter Filter
		want   string
	}{
		{filter: Literal(`/a"b`), want: `(allow file-read* (literal "/a\"b"))`},
		{filter: Subpath(`/a\b`), want: `(allow file-read* (subpath "/a\\b"))`},
		{
			filter: Subpath(`/q"))(allow file-read*)(allow file-write*);\x`),
			want:   `(allow file-read* (subpath "/q\"))(allow file-read*)(allow file-write*);\\x"))`,
		},
	}

	for _, tt := range tests {
		if got := Allow(FileRead, tt.filter).String(); got != tt.want {
			t.Errorf("rule = %s, want %s", got, tt.want)
		}
	}
}
