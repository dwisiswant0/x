package bump

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestModChanges(t *testing.T) {
	t.Parallel()

	before := parseModFile(t, `module example.com/main

go 1.24.0

require (
	example.com/gone v1.0.0
	example.com/lib v1.0.0
	example.com/same v1.0.0
)
`)
	after := parseModFile(t, `module example.com/main

go 1.25.0

toolchain go1.26.2

require (
	example.com/dep v1.0.0 // indirect
	example.com/lib v1.1.0
	example.com/same v1.0.0
)
`)
	want := []Change{
		{"go", "1.24.0", "1.25.0"},
		{"toolchain", "", "go1.26.2"},
		{"example.com/dep", "", "v1.0.0"},
		{"example.com/gone", "v1.0.0", ""},
		{"example.com/lib", "v1.0.0", "v1.1.0"},
	}

	got := modChanges(before, after)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modChanges:\n got %+v\nwant %+v", got, want)
	}

	if cs := modChanges(before, before); len(cs) != 0 {
		t.Errorf("modChanges(f, f) = %+v, want none", cs)
	}
}

func TestGoEnvCheck(t *testing.T) {
	t.Parallel()

	const gomod = "/m/go.mod"

	for _, tc := range []struct {
		env  goEnv
		want error
	}{
		{goEnv{GOMOD: gomod}, nil},
		{goEnv{GOMOD: gomod, GOWORK: "off"}, nil},
		{goEnv{GOMOD: ""}, errNoModule},
		{goEnv{GOMOD: os.DevNull}, errNoModule},
		{goEnv{GOMOD: gomod, GOWORK: "/m/go.work"}, errWorkspace},
	} {
		if err := tc.env.check(); !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) {
			t.Errorf("%+v.check() = %v, want %v", tc.env, err, tc.want)
		}
	}
}

func TestSwitchesToolchains(t *testing.T) {
	t.Parallel()

	for v, want := range map[string]bool{
		"auto":          true,
		"path":          true,
		"go1.26.0+auto": true,
		"local+path":    true,
		"local":         false,
		"go1.26.0":      false,
		"":              false,
	} {
		if got := switchesToolchains(v); got != want {
			t.Errorf("switchesToolchains(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestDecodeScan(t *testing.T) {
	t.Parallel()

	stream := strings.Join([]string{
		`{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}`,
		`{"progress":{"message":"Scanning..."}}`,
		`{"osv":{"id":"GO-0000-0001","modified":"2024-01-01T00:00:00Z","details":"","affected":[]}}`,
		`{"finding":{"osv":"GO-0000-0001","trace":[{"module":"example.com/lib","version":"v1.0.0"}]}}`,
		`{"finding":{"osv":"GO-0000-0001","trace":[` +
			`{"module":"example.com/lib","version":"v1.0.0","package":"example.com/lib/vuln"}]}}`,
	}, "\n")

	res, err := decodeScan(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := res.osvs["GO-0000-0001"]; !ok || len(res.osvs) != 1 {
		t.Errorf("osvs = %v, want GO-0000-0001 only", res.osvs)
	}

	if len(res.findings) != 2 {
		t.Errorf("got %d findings, want 2", len(res.findings))
	}

	if _, err := decodeScan(strings.NewReader(`{"config":`)); err == nil || errors.Is(err, errProtocol) {
		t.Errorf("decodeScan of a truncated stream = %v, want a decoding error", err)
	}

	for _, stream := range []string{
		"",
		`{"progress":{"message":"Scanning..."}}`,
		`{"config":{"protocol_version":"v2.0.0"}}`,
	} {
		if _, err := decodeScan(strings.NewReader(stream)); !errors.Is(err, errProtocol) {
			t.Errorf("decodeScan(%q) = %v, want %v", stream, err, errProtocol)
		}
	}
}
