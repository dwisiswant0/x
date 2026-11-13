package cache

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
)

// These tests use real sockets, so they run outside synctest bubbles.

func gzipped(tb testing.TB, text string) []byte {
	tb.Helper()

	var buf bytes.Buffer

	zw := gzip.NewWriter(&buf)
	_, _ = io.WriteString(zw, text)

	err := zw.Close()
	if err != nil {
		tb.Fatal(err)
	}

	return buf.Bytes()
}

// newGzipServer starts a server that answers with a gzipped "hello" that is
// fresh for 100 seconds, and with a 304 to If-None-Match. It returns the
// server, the number of requests it has received, and the body it sends.
func newGzipServer(t *testing.T) (*httptest.Server, *atomic.Int32, []byte) {
	t.Helper()

	compressed := gzipped(t, bodyHello)

	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		writer.Header().Set(hdrContentEncoding, "gzip")
		writer.Header().Set(hdrETag, etagA)

		if req.Header.Get(hdrIfNoneMatch) == etagA {
			writer.Header().Set(hdrCacheControl, "max-age=100")
			writer.Header().Set("X-Version", "2")
			writer.WriteHeader(http.StatusNotModified)

			return
		}

		writer.Header().Set(hdrCacheControl, "max-age=100")
		writer.Header().Set("X-Version", "1")
		_, _ = writer.Write(compressed)
	}))
	t.Cleanup(srv.Close)

	return srv, &hits, compressed
}

func TestDecodedBody(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.2-omit", "9111-3.2-omit-limit")

	srv, hits, _ := newGzipServer(t)

	// Go's transport asks for gzip and decodes the body.
	cache, err := New(srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}

	get(t, cache, srv.URL)

	res, body := get(t, cache, srv.URL)
	if hits.Load() != 1 || body != bodyHello || !res.Uncompressed {
		t.Errorf("hit: %d origin requests, body %q, Uncompressed %t", hits.Load(), body, res.Uncompressed)
	}

	wantHeader(t, res, hdrContentEncoding, "")

	// A 304 doesn't add Content-Encoding to the decoded body, but updates
	// the other fields.
	res, body = get(t, cache, srv.URL, hdrCacheControl, ccNoCache)
	if hits.Load() != 2 || body != bodyHello {
		t.Errorf("validated: %d origin requests, body %q", hits.Load(), body)
	}

	wantHeader(t, res, hdrContentEncoding, "")
	wantHeader(t, res, "X-Version", "2")
}

func TestEncodedBodyStoredAsReceived(t *testing.T) {
	t.Parallel()

	srv, _, compressed := newGzipServer(t)

	// Without transparent decoding, the content is stored as received.
	cache, err := New(newTransport(t, true), WithShared())
	if err != nil {
		t.Fatal(err)
	}

	get(t, cache, srv.URL, "Accept-Encoding", "gzip")

	res, body := get(t, cache, srv.URL, "Accept-Encoding", "gzip")
	if body != string(compressed) || res.Uncompressed {
		t.Errorf("not decoded: body %q, Uncompressed %t", body, res.Uncompressed)
	}

	wantHeader(t, res, hdrContentEncoding, "gzip")
}

func TestHostKeys(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-uri")

	newServer := func(name string) (*httptest.Server, *atomic.Int32) {
		var hits atomic.Int32

		srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			writer.Header().Set(hdrCacheControl, ccMaxAge60)
			_, _ = io.WriteString(writer, name)
		}))
		t.Cleanup(srv.Close)

		return srv, &hits
	}

	srvA, aHits := newServer("a")
	srvB, bHits := newServer("b")

	cache, err := New(newTransport(t, false))
	if err != nil {
		t.Fatal(err)
	}

	// Both servers get the same Host header, but are different backends.
	for _, srv := range []*httptest.Server{srvA, srvB, srvA, srvB} {
		req := newRequest(http.MethodGet, srv.URL+"/r")
		req.Host = hostExample

		want := "a"
		if srv == srvB {
			want = "b"
		}

		if _, body := roundTrip(t, cache, req); body != want {
			t.Errorf("%s with Host example.com: body %q", srv.URL, body)
		}
	}

	if aHits.Load() != 1 || bHits.Load() != 1 {
		t.Errorf("origin requests: a %d, b %d; want 1 each", aHits.Load(), bHits.Load())
	}
}

func TestReverseProxy(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.1-connection")

	var hits atomic.Int32

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		writer.Header().Set(hdrCacheControl, ccMaxAge60)
		writer.Header().Set(hdrConnection, hdrXHop)
		writer.Header().Set(hdrXHop, "1")
		writer.Header().Set("X-Origin", "1")
		_, _ = io.WriteString(writer, bodyText)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	cache, err := New(newTransport(t, true), WithShared())
	if err != nil {
		t.Fatal(err)
	}

	// ReverseProxy.Director is deprecated, and a literal that lists every
	// field would have to name it.
	reverse := new(httputil.ReverseProxy)
	reverse.Rewrite = func(req *httputil.ProxyRequest) { req.SetURL(target) }
	reverse.Transport = cache
	// ReverseProxy and ModifyResponse change res.Header after RoundTrip
	// returns. The stored header must not see those changes.
	reverse.ModifyResponse = func(res *http.Response) error {
		res.Header.Add("X-Proxy", "1")

		return nil
	}

	proxy := httptest.NewServer(reverse)
	defer proxy.Close()

	for idx := range 3 {
		res, body := get(t, proxy.Client().Transport, proxy.URL+"/r")
		if body != bodyText {
			t.Errorf("request %d: body %q", idx, body)
		}

		if got := res.Header.Values("X-Proxy"); len(got) != 1 {
			t.Errorf("request %d: X-Proxy = %q", idx, got)
		}

		wantHeader(t, res, hdrXHop, "")
		wantHeader(t, res, "X-Origin", "1")
	}

	if hits.Load() != 1 {
		t.Errorf("backend received %d requests, want 1", hits.Load())
	}
}
