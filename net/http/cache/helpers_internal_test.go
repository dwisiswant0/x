package cache

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

const testURL = "http://example.com/r"

// Header field names and values the tests repeat.
const (
	hdrAccept            = "Accept"
	hdrAge               = "Age"
	hdrAuthorization     = "Authorization"
	hdrCacheControl      = "Cache-Control"
	hdrConnection        = "Connection"
	hdrContentEncoding   = "Content-Encoding"
	hdrContentLength     = "Content-Length"
	hdrContentType       = "Content-Type"
	hdrDate              = "Date"
	hdrETag              = "ETag"
	hdrExpires           = "Expires"
	hdrFoo               = "Foo"
	hdrIfModifiedSince   = "If-Modified-Since"
	hdrIfNoneMatch       = "If-None-Match"
	hdrLastModified      = "Last-Modified"
	hdrProxyAuthenticate = "Proxy-Authenticate"
	hdrSetCookie         = "Set-Cookie"
	hdrUpgrade           = "Upgrade"
	hdrXHop              = "X-Hop"

	ccMaxAge            = "max-age"
	ccMaxAge0           = "max-age=0"
	ccMaxAge1           = "max-age=1"
	ccMaxAge60          = "max-age=60"
	ccMaxAge1Revalidate = "max-age=1, must-revalidate"
	ccMaxStale          = "max-stale"
	ccNoCache           = "no-cache"
	ccNoStore           = "no-store"
	ccNoStoreMaxAge600  = "no-store, max-age=600"
	ccPrivate           = "private"
	ccPublic            = "public"
	ccSMaxAge60         = "s-maxage=60"

	etagA  = `"a"`
	etagB  = `"b"`
	etagV1 = `"v1"`

	typeHTML  = "text/html"
	typePlain = "text/plain"

	varyAcceptFoo = "Accept, Foo"
)

// Other strings the tests repeat.
const (
	bodyHello    = "hello"
	cookieSecret = "sid=secret"
	bodyText     = "body"
	hostExample  = "example.com"
	// hostBackend and hostBackend2 are the addresses of two backends of a
	// proxy that forwards requests for hostExample.
	hostBackend  = "10.0.0.1"
	hostBackend2 = "10.0.0.2"
	urlExampleA  = "http://example.com/a"

	dateRFC850 = "Sunday, 06-Nov-94 08:49:37 GMT"
	dateIMF    = "Sun, 06 Nov 1994 08:49:37 GMT"
	dateANSIC  = "Sun Nov  6 08:49:37 1994"
)

// origin is an in-memory origin server. It records the requests it receives
// and answers them with handler.
type origin struct {
	handler http.HandlerFunc

	mu   sync.Mutex
	reqs []*http.Request
	err  error
}

func (o *origin) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}

	o.mu.Lock()
	o.reqs = append(o.reqs, req.Clone(context.Background()))
	err := o.err
	o.mu.Unlock()

	if err != nil {
		return nil, err
	}

	rec := httptest.NewRecorder()
	o.handler(rec, req)
	res := rec.Result()

	res.Request = req
	if req.Method == http.MethodHead {
		res.Body = http.NoBody
	}

	return res, nil
}

// hits returns the number of requests the origin has received.
func (o *origin) hits() int {
	o.mu.Lock()
	defer o.mu.Unlock()

	return len(o.reqs)
}

// fail makes the origin answer every later request with err.
func (o *origin) fail(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.err = err
}

// last returns the most recent request the origin received.
func (o *origin) last() *http.Request {
	o.mu.Lock()
	defer o.mu.Unlock()

	if len(o.reqs) == 0 {
		return nil
	}

	return o.reqs[len(o.reqs)-1]
}

func newTestCache(tb testing.TB, handler http.HandlerFunc, opts ...Option) (*Transport, *origin) {
	tb.Helper()

	srv := &origin{handler: handler, mu: sync.Mutex{}, reqs: nil, err: nil}

	cache, err := New(srv, opts...)
	if err != nil {
		tb.Fatal(err)
	}

	return cache, srv
}

// newTransport returns a copy of [http.DefaultTransport] that ignores the
// proxy environment variables. It decodes gzip responses itself unless
// compression is disabled.
func newTransport(tb testing.TB, disableCompression bool) *http.Transport {
	tb.Helper()

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		tb.Fatalf("http.DefaultTransport is a %T, want *http.Transport", http.DefaultTransport)
	}

	transport := base.Clone()
	transport.Proxy = nil
	transport.DisableCompression = disableCompression

	return transport
}

// pairs yields the name-value pairs of fields, which must have an even
// length.
func pairs(fields []string) iter.Seq2[string, string] {
	if len(fields)%2 != 0 {
		panic("odd number of name-value fields")
	}

	return func(yield func(string, string) bool) {
		for len(fields) >= 2 {
			if !yield(fields[0], fields[1]) {
				return
			}

			fields = fields[2:]
		}
	}
}

// respond returns a handler that answers with status, body, and the header
// fields given as name-value pairs.
//
// A test that echoes part of a request in body passes it through
// html.EscapeString, which leaves the values the tests use unchanged. Without
// it, gosec reports the write as cross-site scripting (G705), and not on
// every run.
func respond(status int, body string, fields ...string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		for name, value := range pairs(fields) {
			writer.Header().Add(name, value)
		}

		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	}
}

// sequence returns a handler that answers the nth request with the nth
// handler, and later requests with the last one.
func sequence(handlers ...http.HandlerFunc) http.HandlerFunc {
	var lock sync.Mutex

	count := 0

	return func(writer http.ResponseWriter, req *http.Request) {
		lock.Lock()

		handler := handlers[min(count, len(handlers)-1)]
		count++

		lock.Unlock()

		handler(writer, req)
	}
}

// newRequest returns a request with the header fields given as name-value
// pairs.
func newRequest(method, url string, fields ...string) *http.Request {
	return newRequestContext(context.Background(), method, url, fields...)
}

// newRequestContext is newRequest with a context, for a request that a
// handler sends while it answers another.
func newRequestContext(ctx context.Context, method, url string, fields ...string) *http.Request {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		panic(err)
	}

	for name, value := range pairs(fields) {
		req.Header.Add(name, value)
	}

	return req
}

// reply is the part of an [http.Response] the tests inspect after roundTrip
// has read and closed its body.
type reply struct {
	StatusCode   int
	Header       http.Header
	Trailer      http.Header
	Uncompressed bool
}

// roundTrip sends req through rt and reads the whole response body.
func roundTrip(tb testing.TB, rt http.RoundTripper, req *http.Request) (reply, string) {
	tb.Helper()

	res, err := rt.RoundTrip(req)
	if err != nil {
		tb.Fatal(err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		tb.Fatal(err)
	}

	err = res.Body.Close()
	if err != nil {
		tb.Fatal(err)
	}

	return reply{
		StatusCode:   res.StatusCode,
		Header:       res.Header,
		Trailer:      res.Trailer,
		Uncompressed: res.Uncompressed,
	}, string(body)
}

// get sends a GET request for url with the given header fields through rt.
func get(tb testing.TB, rt http.RoundTripper, url string, fields ...string) (reply, string) {
	tb.Helper()

	return roundTrip(tb, rt, newRequest(http.MethodGet, url, fields...))
}

// wantHits fails the test unless the origin has received n requests.
func wantHits(tb testing.TB, srv *origin, n int) {
	tb.Helper()

	if got := srv.hits(); got != n {
		tb.Fatalf("origin received %d requests, want %d", got, n)
	}
}

func wantHeader(tb testing.TB, res reply, name, want string) {
	tb.Helper()

	if got := res.Header.Get(name); got != want {
		tb.Errorf("%s = %q, want %q", name, got, want)
	}
}

var errOffline = errors.New("origin offline")
