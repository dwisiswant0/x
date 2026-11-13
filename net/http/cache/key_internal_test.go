package cache

import (
	"net/http"
	"testing"
)

func TestKey(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-uri")

	key := func(rawURL, host string) string {
		t.Helper()

		req := newRequest(http.MethodGet, rawURL)
		req.Host = host

		tgt, ok := newTarget(req)
		if !ok {
			return ""
		}

		return tgt.key(req.URL.RequestURI())
	}

	same := [][2]string{
		{"http://example.com/a?x=1", "HTTP://EXAMPLE.COM:80/a?x=1"},
		{"https://example.com/", "https://example.com:443"},
		{"http://example.com:/a", urlExampleA},
		{"http://example.com/a#frag", "http://user:pass@example.com/a"},
	}
	for _, p := range same {
		if a, b := key(p[0], ""), key(p[1], ""); a != b {
			t.Errorf("key(%q) = %q, key(%q) = %q; want equal", p[0], a, p[1], b)
		}
	}

	different := [][2]string{
		{urlExampleA, "https://example.com/a"},
		{urlExampleA, "http://example.com:8080/a"},
		{"http://example.com/a?x=1", "http://example.com/a?x=2"},
		{"http://example.com/a?x=1&y=2", "http://example.com/a?y=2&x=1"},
		{urlExampleA, "http://example.com/A"},
		{"http://example.com/a%2Fb", "http://example.com/a/b"},
		{"http://example.com/a?", urlExampleA},
	}
	for _, p := range different {
		if a, b := key(p[0], ""), key(p[1], ""); a == b {
			t.Errorf("key(%q) = key(%q) = %q; want different", p[0], p[1], a)
		}
	}

	// The Host header names the authority, whichever server the request is
	// sent to.
	for _, rawURL := range []string{urlExampleA, "http://10.0.0.1/a", "http://10.0.0.2:8080/a"} {
		if a, b := key(rawURL, "Example.com:80"), key(urlExampleA, ""); a != b {
			t.Errorf("%s with Host example.com: key %q, want %q", rawURL, a, b)
		}
	}

	for _, rawURL := range []string{"ftp://example.com/a", "file:///etc/passwd"} {
		if k := key(rawURL, ""); k != "" {
			t.Errorf("key(%q) = %q, want no key", rawURL, k)
		}
	}
}

func TestDialHost(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		url, host, want string
	}{
		{urlExampleA, "", ""},
		{urlExampleA, "EXAMPLE.com:80", ""},
		{"http://10.0.0.1/a", hostExample, hostBackend},
		{"https://10.0.0.1:443/a", hostExample, hostBackend},
		{"http://10.0.0.1:8080/a", hostExample, "10.0.0.1:8080"},
	} {
		req := newRequest(http.MethodGet, test.url)

		req.Host = test.host
		if got := dialHost(req); got != test.want {
			t.Errorf("dialHost(%s, Host %q) = %q, want %q", test.url, test.host, got, test.want)
		}
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-cross-origin")

	req := newRequest(http.MethodPost, "http://example.com/a/b?q=1")

	tgt, _ := newTarget(req)
	for _, test := range []struct {
		ref  string
		want string
	}{
		{"", ""},
		{"/c", "http://example.com/c"},
		{"c", "http://example.com/a/c"},
		{"?q=2", "http://example.com/a/b?q=2"},
		{"http://EXAMPLE.com:80/d", "http://example.com/d"},
		{"https://example.com/d", ""},
		{"http://example.com:8080/d", ""},
		{"http://other.example/d", ""},
		{"//other.example/d", ""},
		{"http://[::1", ""},
	} {
		got, ok := tgt.resolve(req, test.ref)
		if ok != (test.want != "") || got != test.want {
			t.Errorf("resolve(%q) = %q, %t; want %q", test.ref, got, ok, test.want)
		}
	}
}
