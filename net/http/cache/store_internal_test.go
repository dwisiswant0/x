package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// storableCase is a response, and whether a private and a shared cache may
// store it.
type storableCase struct {
	name    string
	status  int
	fields  []string
	auth    bool
	private bool
	shared  bool
}

func storableCases() []storableCase {
	const lastMod = "Wed, 31 Dec 2025 00:00:00 GMT"

	return []storableCase{
		{"1xx isn't final", 103, []string{hdrCacheControl, ccMaxAge60}, false, false, false},
		{"206 isn't understood", 206, []string{hdrCacheControl, ccMaxAge60}, false, false, false},
		{"304 isn't understood", 304, []string{hdrCacheControl, ccMaxAge60}, false, false, false},
		{
			"must-understand with an unknown status", 299,
			[]string{hdrCacheControl, "max-age=60, must-understand"}, false, false, false,
		},
		{
			"must-understand overrides no-store", 200,
			[]string{hdrCacheControl, "max-age=60, no-store, must-understand"}, false, true, true,
		},
		{ccNoStore, 200, []string{hdrCacheControl, "max-age=60, no-store"}, false, false, false},
		{"unknown final status with max-age", 299, []string{hdrCacheControl, ccMaxAge60}, false, true, true},
		{ccPrivate, 200, []string{hdrCacheControl, "private, max-age=60"}, false, true, false},
		{"qualified private", 200, []string{hdrCacheControl, `private="Set-Cookie", max-age=60`}, false, true, false},
		{hdrAuthorization, 200, []string{hdrCacheControl, ccMaxAge60}, true, true, false},
		{"Authorization with public", 200, []string{hdrCacheControl, "public, max-age=60"}, true, true, true},
		{
			"Authorization with must-revalidate", 200,
			[]string{hdrCacheControl, "must-revalidate, max-age=60"}, true, true, true,
		},
		{"Authorization with s-maxage", 200, []string{hdrCacheControl, ccSMaxAge60}, true, false, true},
		{ccPublic, 299, []string{hdrCacheControl, ccPublic, hdrLastModified, lastMod}, false, true, true},
		{
			"private makes a private cache store", 299,
			[]string{hdrCacheControl, ccPrivate, hdrLastModified, lastMod}, false, true, false,
		},
		{hdrExpires, 201, []string{hdrExpires, "Fri, 02 Jan 2026 00:00:00 GMT"}, false, true, true},
		{ccMaxAge, 201, []string{hdrCacheControl, ccMaxAge60}, false, true, true},
		{"s-maxage", 201, []string{hdrCacheControl, ccSMaxAge60}, false, false, true},
		{"heuristically cacheable status", 404, []string{hdrLastModified, lastMod}, false, true, true},
		{"nothing allows storing", 201, []string{hdrLastModified, lastMod}, false, false, false},
		{"no freshness and no validator", 200, nil, false, false, false},
		{"stale but validatable", 200, []string{hdrCacheControl, ccMaxAge0, hdrETag, etagA}, false, true, true},
		{"Vary: *", 200, []string{hdrCacheControl, ccMaxAge60, "Vary", "*"}, false, false, false},
	}
}

func TestStorable(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-3-final-status",
		"9111-3-understood-status",
		"9111-3-no-store",
		"9111-3-shared-private",
		"9111-3-shared-auth",
		"9111-3-public",
		"9111-3-private-explicit",
		"9111-3-expires",
		"9111-3-max-age",
		"9111-3-s-maxage",
		"9111-3-heuristic-status",
		"9111-3.5-authorization",
		"9111-5.2.2.3-ignore-no-store",
		"9111-5.2.2.5-no-store",
		"9111-5.2.2.7-shared",
		"9111-5.2.2.7-private-cache",
		"9111-5.2.2.7-qualified",
		"9111-5.2.2.9-public",
	)

	for _, test := range storableCases() {
		stored := testVariant(test.status, 0, nil, append(test.fields, hdrDate, "Thu, 01 Jan 2026 00:00:00 GMT")...)

		stored.authorized = test.auth
		if got := storable(stored, false); got != test.private {
			t.Errorf("%s: private cache storable = %t, want %t", test.name, got, test.private)
		}

		stored.derived = derive(stored.header, stored.status, stored.requestTime, stored.responseTime, true)
		if got := storable(stored, true); got != test.shared {
			t.Errorf("%s: shared cache storable = %t, want %t", test.name, got, test.shared)
		}
	}
}

func TestWithAge(t *testing.T) {
	t.Parallel()

	stored := http.Header{"A": {"1", "2"}, hdrAge: {"5"}, "B": nil, "C": {"3"}}
	got := withAge(stored, "7")

	want := http.Header{"A": {"1", "2"}, hdrAge: {"7"}, "B": nil, "C": {"3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("withAge = %v, want %v", got, want)
	}

	// The copy's values can grow without overwriting each other or the
	// stored header.
	got["A"] = append(got["A"], "x")
	got[hdrAge] = append(got[hdrAge], "y")

	if got.Get("B") != "" || got.Get("C") != "3" || stored.Get(hdrAge) != "5" || len(stored["A"]) != 2 {
		t.Errorf("growing the copy changed it to %v, and the stored header to %v", got, stored)
	}
}

func TestStoredHeader(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-3.1-all-fields",
		"9111-3.1-connection",
		"9111-3.1-hop-by-hop",
		"9111-3.1-proxy-fields",
		"9110-7.6.1-connection-fields",
		"9110-7.6.1-hop-by-hop",
	)

	got := storedHeader(http.Header{
		hdrConnection:               {"close, X-Conn", "x-other"},
		"X-Conn":                    {"1"},
		"X-Other":                   {"1"},
		"Keep-Alive":                {"timeout=5"},
		"Proxy-Connection":          {"keep-alive"},
		"Te":                        {"trailers"},
		"Transfer-Encoding":         {"chunked"},
		hdrUpgrade:                  {"h2c"},
		hdrProxyAuthenticate:        {"Basic"},
		"Proxy-Authentication-Info": {"x"},
		"Proxy-Authorization":       {"Basic x"},
		hdrSetCookie:                {"a=1", "b=2"},
		"X-Unknown-Field":           {"kept"},
		hdrContentType:              {typePlain},
	})

	want := http.Header{
		hdrSetCookie:      {"a=1", "b=2"},
		"X-Unknown-Field": {"kept"},
		hdrContentType:    {typePlain},
	}
	if len(got) != len(want) {
		t.Fatalf("storedHeader = %v, want %v", got, want)
	}

	for name, values := range want {
		if g := got.Values(name); strings.Join(g, "|") != strings.Join(values, "|") {
			t.Errorf("%s = %q, want %q", name, g, values)
		}
	}
}

func TestUpdatedHeader(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.2-update", "9111-3.2-omit", "9111-3.2-omit-limit", "9111-3.2-content-range")

	stored := http.Header{
		hdrAge:             {"30"},
		hdrCacheControl:    {ccMaxAge1},
		hdrContentEncoding: {"gzip"},
		hdrContentLength:   {"5"},
		hdrContentType:     {typePlain},
		"Etag":             {etagA},
		"X-Kept":           {"stored"},
	}
	received := http.Header{
		hdrCacheControl:      {ccMaxAge60},
		hdrConnection:        {hdrXHop},
		hdrXHop:              {"1"},
		hdrContentEncoding:   {"br"},
		hdrContentLength:     {"0"},
		"Content-Range":      {"bytes 0-1/5"},
		hdrContentType:       {typeHTML},
		hdrProxyAuthenticate: {"Basic"},
		"X-New":              {"1", "2"},
	}

	got := updatedHeader(stored, received, false)
	for name, want := range map[string]string{
		hdrAge:               "",
		hdrCacheControl:      ccMaxAge60,
		hdrContentEncoding:   "br",
		hdrContentLength:     "5",
		"Content-Range":      "",
		hdrContentType:       typeHTML,
		"Etag":               etagA,
		hdrProxyAuthenticate: "",
		hdrXHop:              "",
		"X-Kept":             "stored",
		"X-New":              "1|2",
	} {
		if g := strings.Join(got.Values(name), "|"); g != want {
			t.Errorf("%s = %q, want %q", name, g, want)
		}
	}

	if stored.Get(hdrCacheControl) != ccMaxAge1 {
		t.Error("updatedHeader modified the stored header")
	}

	// A decoded body keeps its Content-Encoding, the only field it omits.
	decoded := updatedHeader(http.Header{hdrContentType: {typePlain}}, received, true)
	if v := decoded.Get(hdrContentEncoding); v != "" {
		t.Errorf("decoded body got Content-Encoding %q", v)
	}

	if v := decoded.Get(hdrContentType); v != typeHTML {
		t.Errorf("decoded body: Content-Type = %q, want text/html", v)
	}
}

var (
	errReadFailed  = errors.New("read failed")
	errBodyTooLong = errors.New("body longer than Content-Length")
)

// newCaptureBody returns a captureBody that reads body, with the limit and
// the Content-Length want, and passes the complete body to commit.
func newCaptureBody(body io.Reader, limit, want int64, commit func([]byte)) *captureBody {
	return &captureBody{
		ReadCloser: io.NopCloser(body),
		limit:      limit,
		want:       want,
		commit:     commit,
		mu:         sync.Mutex{},
		buf:        nil,
		done:       false,
		chunks:     nil,
		held:       0,
	}
}

func TestCaptureBody(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.3-no-incomplete-use")

	for _, test := range []struct {
		name   string
		body   io.Reader
		want   int64
		limit  int64
		close  bool
		commit bool
	}{
		{"complete, known length", strings.NewReader(bodyHello), 5, 10, false, true},
		{"complete, unknown length", strings.NewReader(bodyHello), -1, 10, false, true},
		{"at the limit", strings.NewReader(bodyHello), -1, 5, false, true},
		{"short", strings.NewReader("hel"), 5, 10, false, false},
		// The body is complete at its Content-Length.
		{"long", strings.NewReader("hello!"), 5, 10, false, true},
		{"over the limit", strings.NewReader(bodyHello), -1, 4, false, false},
		{"read error", io.MultiReader(strings.NewReader("hel"), iotest.ErrReader(errReadFailed)), -1, 10, false, false},
		{"closed early", strings.NewReader(bodyHello), 5, 10, true, false},
	} {
		var committed []byte

		capture := newCaptureBody(iotest.OneByteReader(test.body), test.limit, test.want,
			func(body []byte) { committed = body })

		if test.close {
			buf := make([]byte, 2)
			_, _ = capture.Read(buf)
			_ = capture.Close()
		}

		got, _ := io.ReadAll(capture)
		if !test.close && !strings.HasPrefix(string(got), "hel") {
			t.Errorf("%s: caller read %q", test.name, got)
		}

		if (committed != nil) != test.commit {
			t.Errorf("%s: committed %q, want commit = %t", test.name, committed, test.commit)
		}

		if test.commit && string(committed) != bodyHello {
			t.Errorf("%s: committed %q, want %q", test.name, committed, bodyHello)
		}
	}
}

func TestCaptureBodyLargeBody(t *testing.T) {
	t.Parallel()

	// Go rounds a large allocation up to a multiple of its 8 KiB pages, so a
	// copy can keep less than a page spare.
	const page = 8 << 10

	// Neither length is a multiple of page. The long body is kept in chunks
	// if its length is unknown (see TestCaptureBodyChunks).
	long := bytes.Repeat([]byte("0123456789"), captureStart/2+100)
	short := long[:captureStart*5/8+100]

	for _, test := range []struct {
		data     []byte
		want     int64
		maxSpare int
	}{
		// A complete body of known length fills its copy exactly.
		{long, int64(len(long)), 0},
		{long, -1, 0},
		{short, -1, page - 1},
	} {
		var committed []byte

		// The last bytes arrive with io.EOF, as some bodies return them.
		capture := newCaptureBody(iotest.DataErrReader(bytes.NewReader(test.data)), 1<<20, test.want,
			func(body []byte) { committed = body })
		_, _ = io.ReadAll(capture)

		if !bytes.Equal(committed, test.data) {
			t.Errorf("%d bytes, Content-Length %d: committed %d bytes, want the bytes sent",
				len(test.data), test.want, len(committed))
		}

		if spare := cap(committed) - len(committed); spare > test.maxSpare {
			t.Errorf("%d bytes, Content-Length %d: committed body has room for %d more bytes, want at most %d",
				len(test.data), test.want, spare, test.maxSpare)
		}
	}
}

func TestCaptureBodyChunks(t *testing.T) {
	t.Parallel()

	// A copy of unknown length longer than captureStart is kept in chunks,
	// whatever the sizes of the reads, and committed whole and exact.
	long := bytes.Repeat([]byte("0123456789"), captureStart/2+100)
	justOver := long[:captureStart+10]

	for _, test := range []struct {
		data   []byte
		limit  int64
		read   int
		commit bool
	}{
		{long, 1 << 20, 1000, true},
		{long, 1 << 20, 7 << 10, true},
		{long, 1 << 20, captureStart + 3, true},
		{long, 1 << 20, 1 << 20, true},
		{long, int64(len(long)), 7 << 10, true},
		{long, int64(len(long)) - 1, 7 << 10, false},
		{justOver, int64(len(justOver)), captureStart, true},
		{justOver, int64(len(justOver)) - 1, captureStart, false},
	} {
		var committed []byte

		capture := newCaptureBody(bytes.NewReader(test.data), test.limit, -1, func(body []byte) { committed = body })

		// Hide io.Discard's ReadFrom, so that CopyBuffer reads with buf.
		_, _ = io.CopyBuffer(struct{ io.Writer }{io.Discard}, capture, make([]byte, test.read))

		// A copy that is committed or discarded is released.
		if capture.buf != nil || capture.chunks != nil || capture.held != 0 {
			t.Errorf("%d bytes, limit %d: the capture still holds its copy", len(test.data), test.limit)
		}

		switch {
		case !test.commit && committed != nil:
			t.Errorf("%d bytes, limit %d: committed %d bytes, want none", len(test.data), test.limit, len(committed))
		case test.commit && !bytes.Equal(committed, test.data):
			t.Errorf("%d bytes in reads of %d: committed %d bytes, want the bytes sent",
				len(test.data), test.read, len(committed))
		case cap(committed) != len(committed):
			t.Errorf("%d bytes in reads of %d: committed body has room for %d more bytes",
				len(test.data), test.read, cap(committed)-len(committed))
		}
	}
}

func TestGrowCapture(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		length, room int
		read         int
		bound        int64
		wantRoom     int
	}{
		{"room left", 10, 20, 5, 100, 20},
		{"grows", 20, 20, 5, 1000, 20 * captureGrowth},
		{"fits a long read", 20, 20, 90, 1000, 110},
		{"stops at the bound", 60, 60, 5, 100, 100},
		{"past the bound", 100, 100, 5, 100, 105},
		{"from nothing", 0, 0, 5, 100, 5},
	} {
		buf := append(make([]byte, 0, test.room), bytes.Repeat([]byte("x"), test.length)...)

		got := growCapture(buf, test.read, test.bound)
		if cap(got) != test.wantRoom || !bytes.Equal(got, buf) {
			t.Errorf("%s: got %d bytes with room for %d, want %d bytes with room for %d",
				test.name, len(got), cap(got), test.length, test.wantRoom)
		}
	}
}

func TestCaptureBodyGrowsAsItArrives(t *testing.T) {
	t.Parallel()

	// The origin says the body is 1 GiB long and sends 100 KiB of it.
	const announced, sent = 1 << 30, 100 << 10

	cache, _ := newTestCache(t, respond(http.StatusOK, strings.Repeat("x", sent),
		hdrCacheControl, ccMaxAge60, hdrContentLength, strconv.Itoa(announced)),
		WithMaxBodySize(announced), WithMaxBytes(announced))

	res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = res.Body.Close() }()

	capture, ok := res.Body.(*captureBody)
	if !ok {
		t.Fatalf("response body is a %T, want a *captureBody", res.Body)
	}

	room := func() int {
		capture.mu.Lock()
		defer capture.mu.Unlock()

		return cap(capture.buf)
	}

	if got := room(); got > captureStart {
		t.Errorf("before the body arrives, the copy has room for %d bytes, want at most %d", got, captureStart)
	}

	_, err = io.ReadFull(res.Body, make([]byte, sent))
	if err != nil {
		t.Fatal(err)
	}

	if got := room(); got > captureGrowth*sent {
		t.Errorf("after %d bytes, the copy has room for %d, want at most %d", sent, got, captureGrowth*sent)
	}
}

func TestCaptureBodyCommitsBeforeEOF(t *testing.T) {
	t.Parallel()

	// A proxy forwards the last bytes before it reads EOF, so the response
	// must be stored by then.
	var committed []byte

	capture := newCaptureBody(strings.NewReader(bodyHello), 10, 5, func(body []byte) { committed = body })

	n, err := capture.Read(make([]byte, 5))
	if n != 5 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}

	if string(committed) != bodyHello {
		t.Errorf("committed %q after Content-Length bytes, want hello", committed)
	}
}

// lastReadErr returns its data, and err with the last of it.
type lastReadErr struct {
	data string
	err  error
}

func (r *lastReadErr) Read(p []byte) (int, error) {
	count := copy(p, r.data)

	r.data = r.data[count:]
	if r.data == "" {
		return count, r.err
	}

	return count, nil
}

func TestCaptureBodyErrorWithLastBytes(t *testing.T) {
	t.Parallel()

	// Go's HTTP/2 transport returns the last declared bytes of a body that
	// runs past its Content-Length together with an error.
	var committed []byte

	capture := newCaptureBody(&lastReadErr{data: bodyHello, err: errBodyTooLong}, 10, 5,
		func(body []byte) { committed = body })

	_, err := capture.Read(make([]byte, 5))
	if !errors.Is(err, errBodyTooLong) {
		t.Fatalf("Read error = %v", err)
	}

	if committed != nil {
		t.Errorf("committed %q despite the read error", committed)
	}
}

func TestCaptureBodyCloseDuringRead(t *testing.T) {
	t.Parallel()

	// Go's response bodies allow Close during a Read. Run with -race.
	capture := newCaptureBody(strings.NewReader(strings.Repeat("x", 1<<16)), 1<<20, -1, func([]byte) {})

	var group sync.WaitGroup

	group.Go(func() {
		buf := make([]byte, 16)

		for {
			_, err := capture.Read(buf)
			if err != nil {
				return
			}
		}
	})

	_ = capture.Close()

	group.Wait()
}

func TestCaptureBodyReturnsErrorsUnchanged(t *testing.T) {
	t.Parallel()

	// httputil.ReverseProxy compares body errors with ==, for example to skip
	// logging a client that went away.
	capture := newCaptureBody(&lastReadErr{data: bodyHello, err: context.Canceled}, 10, -1, func([]byte) {})

	_, err := capture.Read(make([]byte, 5))
	if !errors.Is(err, context.Canceled) || errors.Unwrap(err) != nil {
		t.Errorf("Read error = %v, want context.Canceled itself", err)
	}
}

func TestCaptureBodyWrappedEOFIsNotTheEnd(t *testing.T) {
	t.Parallel()

	// io.Reader returns io.EOF itself at the end. A wrapped EOF reports a
	// failure, so the body may be truncated.
	errWrappedEOF := fmt.Errorf("connection closed: %w", io.EOF)

	var committed []byte

	capture := newCaptureBody(&lastReadErr{data: bodyHello, err: errWrappedEOF}, 10, -1,
		func(body []byte) { committed = body })

	_, err := capture.Read(make([]byte, 5))
	if !errors.Is(err, errWrappedEOF) {
		t.Errorf("Read error = %v, want the wrapped EOF", err)
	}

	if committed != nil {
		t.Errorf("committed %q at a wrapped EOF", committed)
	}
}
