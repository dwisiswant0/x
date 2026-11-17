package cache

import (
	"errors"
	"html"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for _, opt := range []Option{
		WithMaxEntries(0), WithMaxEntries(-1), WithMaxBodySize(-1), WithMaxVariants(0), WithMaxVariants(-1),
		WithMaxBytes(0), WithMaxBytes(-1),
	} {
		_, err := New(nil, opt)
		if !errors.Is(err, ErrInvalidOption) {
			t.Errorf("New: err = %v, want ErrInvalidOption", err)
		}
	}

	cache, err := New(nil, WithShared(), WithMaxEntries(1), WithMaxBodySize(0), WithMaxVariants(3))
	if err != nil {
		t.Fatal(err)
	}

	if cache.next != http.DefaultTransport || !cache.shared || cache.maxBodySize != 0 || cache.limits.perServer != 3 {
		t.Errorf("New applied options as %+v", cache)
	}
}

func TestMaxBytesLimitsBodySize(t *testing.T) {
	t.Parallel()

	// A body larger than the cache can hold is never stored.
	for _, test := range []struct {
		maxBytes, wantBodySize int64
	}{{10, 10}, {math.MaxInt64, defaultMaxBodySize}} {
		cache, err := New(nil, WithMaxBytes(test.maxBytes))
		if err != nil {
			t.Fatal(err)
		}

		if cache.maxBodySize != test.wantBodySize {
			t.Errorf("with max bytes %d, max body size = %d, want %d", test.maxBytes, cache.maxBodySize, test.wantBodySize)
		}
	}
}

type idleCloser struct {
	origin

	closed bool
}

func (c *idleCloser) CloseIdleConnections() { c.closed = true }

func TestCloseIdleConnections(t *testing.T) {
	t.Parallel()

	next := new(idleCloser)

	cache, err := New(next)
	if err != nil {
		t.Fatal(err)
	}

	cache.CloseIdleConnections()

	if !next.closed {
		t.Error("CloseIdleConnections wasn't forwarded")
	}

	// A RoundTripper without the method is fine too.
	cache, _ = newTestCache(t, respond(200, ""))
	cache.CloseIdleConnections()
}

func TestHEADUsesStoredGET(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-method", "9110-9.3.1-get-reuse", "9110-9.3.2-no-content", "9110-9.3.2-same-headers")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, bodyHello, hdrCacheControl, ccMaxAge60, hdrContentLength, "5",
			hdrContentType, typePlain))
		getRes, _ := get(t, cache, testURL)

		res, body := roundTrip(t, cache, newRequest(http.MethodHead, testURL))
		wantHits(t, srv, 1)

		if res.StatusCode != http.StatusOK || body != "" {
			t.Errorf("HEAD: got %d with body %q", res.StatusCode, body)
		}

		for _, name := range []string{hdrContentLength, hdrContentType, hdrCacheControl, hdrDate} {
			wantHeader(t, res, name, getRes.Header.Get(name))
		}
	})
}

func TestOnlyGETResponsesStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3-method", "9111-4-method")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60))
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut} {
			roundTrip(t, cache, newRequest(method, testURL))
		}

		get(t, cache, testURL)
		wantHits(t, srv, 4)

		// A stored GET response doesn't answer a POST.
		roundTrip(t, cache, newRequest(http.MethodPost, testURL))
		wantHits(t, srv, 5)
	})
}

func TestPassThroughMethods(t *testing.T) {
	t.Parallel()

	covers(t, "9111-1-tunnel", "9110-13.2.1-non-selecting")

	for _, method := range []string{http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA))
				get(t, cache, testURL)

				for range 2 {
					roundTrip(t, cache, newRequest(method, testURL, hdrIfNoneMatch, etagA))
				}

				wantHits(t, srv, 3)

				if got := srv.last().Header.Get(hdrIfNoneMatch); got != etagA {
					t.Errorf("%s: If-None-Match = %q", method, got)
				}

				// They don't invalidate stored responses either.
				get(t, cache, testURL)
				wantHits(t, srv, 3)
			})
		})
	}
}

func TestUnsafeMethodsInvalidate(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target", "9111-4.4-other-uris", "9111-4.4-cross-origin", "9111-4-write-through")

	const (
		other       = "http://example.com/other"
		content     = "http://example.com/content"
		crossOrigin = "http://elsewhere.example/x"
	)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, "M-SEARCH", "get"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
					if req.Method != http.MethodGet {
						respond(201, "", "Location", "/other", "Content-Location", content)(writer, req)

						return
					}

					respond(200, "", hdrCacheControl, ccMaxAge60)(writer, req)
				})

				urls := []string{testURL, other, content, crossOrigin}
				for _, u := range urls {
					get(t, cache, u)
				}

				roundTrip(t, cache, newRequest(method, testURL))
				wantHits(t, srv, 5)

				for _, u := range urls {
					get(t, cache, u)
				}

				// Every URI except the cross-origin one was invalidated.
				wantHits(t, srv, 8)
			})
		})
	}

	synctest.Test(t, func(t *testing.T) {
		// An error response doesn't invalidate.
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodPost {
				respond(500, "")(writer, req)

				return
			}

			respond(200, "", hdrCacheControl, ccMaxAge60)(writer, req)
		})
		get(t, cache, testURL)
		roundTrip(t, cache, newRequest(http.MethodPost, testURL))
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestInFlightResponseNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// The GET's response arrives after a POST to the same URI.
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})

		var gets atomic.Int32

		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodGet && gets.Add(1) == 1 {
				<-release
			}

			respond(200, "", hdrCacheControl, ccMaxAge60)(writer, req)
		})

		done := make(chan error)

		go func() {
			res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
			if err == nil {
				_, err = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}

			done <- err
		}()

		synctest.Wait()
		roundTrip(t, cache, newRequest(http.MethodPost, testURL))
		close(release)

		err := <-done
		if err != nil {
			t.Fatal(err)
		}

		get(t, cache, testURL)
		wantHits(t, srv, 3)
	})
}

func TestInFlightUpdateNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// A 304, or a 200 to a HEAD, arrives after a POST to the same URI. Storing
	// it would make the invalidated response fresh again.
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		var (
			cache *Transport
			srv   *origin
		)

		cache, srv = newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			switch {
			case req.Method == http.MethodPost:
				respond(http.StatusNoContent, "")(writer, req)
			case req.Method == http.MethodHead || req.Header.Get(hdrIfNoneMatch) != "":
				roundTrip(t, cache, newRequestContext(req.Context(), http.MethodPost, testURL))

				status := http.StatusNotModified
				if req.Method == http.MethodHead {
					status = http.StatusOK
				}

				respond(status, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
			default:
				respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
			}
		})
		get(t, cache, testURL)
		roundTrip(t, cache, newRequest(method, testURL, hdrCacheControl, ccNoCache))

		hits := srv.hits()
		if get(t, cache, testURL); srv.hits() == hits {
			t.Errorf("%s: the update was stored after a POST invalidated the response", method)
		}
	}
}

func TestResponseBodyInFlightNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// The GET's body is still being read when the POST completes.
	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, bodyText, hdrCacheControl, ccMaxAge60))

		res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
		if err != nil {
			t.Fatal(err)
		}

		roundTrip(t, cache, newRequest(http.MethodPost, testURL))

		_, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}

		_ = res.Body.Close()

		get(t, cache, testURL)
		wantHits(t, srv, 3)
	})
}

func TestConcurrentRequests(t *testing.T) {
	t.Parallel()

	// Run with -race. Readers and writers share entries without locks.
	var n atomic.Int64

	cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
		body := "v" + strings.Repeat("x", int(n.Add(1)%7))
		respond(200, body, hdrCacheControl, ccMaxAge60, hdrETag, `"`+body+`"`, "Vary", hdrAccept)(writer, req)
	})

	var group sync.WaitGroup
	for i := range 8 {
		group.Go(func() {
			for j := range 200 {
				accept := []string{hdrAccept, string(rune('a' + (i+j)%3))}

				switch j % 5 {
				case 0:
					roundTrip(t, cache, newRequest(http.MethodPost, testURL))
				case 1:
					roundTrip(t, cache, newRequest(http.MethodHead, testURL, accept...))
				default:
					res, body := get(t, cache, testURL, accept...)
					if etag := res.Header.Get(hdrETag); etag != `"`+body+`"` {
						t.Errorf("body %q with ETag %s", body, etag)
					}
				}
			}
		})
	}

	group.Wait()
}

func TestBypass(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.3-no-partial-store", "9111-3.3-206-marking")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Header.Get("Range") != "" {
				respond(206, "el", hdrCacheControl, ccMaxAge60, "Content-Range", "bytes 1-2/5")(writer, req)

				return
			}

			respond(200, bodyHello, hdrCacheControl, ccMaxAge60)(writer, req)
		})

		// A 206 passes through and isn't stored.
		res, body := get(t, cache, testURL, "Range", "bytes=1-2")
		if res.StatusCode != http.StatusPartialContent || body != "el" {
			t.Errorf("Range: got %d %q", res.StatusCode, body)
		}

		wantHeader(t, res, "Content-Range", "bytes 1-2/5")
		get(t, cache, testURL)
		wantHits(t, srv, 2)

		// With a full response stored, these requests still go to the
		// origin.
		for idx, fields := range [][]string{
			{"Range", "bytes=1-2"},
			{"Range", "bytes=1-2", "If-Range", etagA},
			{"If-Range", etagA},
			{hdrUpgrade, "websocket", hdrConnection, hdrUpgrade},
		} {
			get(t, cache, testURL, fields...)
			wantHits(t, srv, 3+idx)
		}

		req := newRequest(http.MethodGet, testURL)
		req.Body = io.NopCloser(strings.NewReader("query"))
		roundTrip(t, cache, req)
		wantHits(t, srv, 7)

		req = newRequest(http.MethodGet, "ftp://example.com/r")
		roundTrip(t, cache, req)
		roundTrip(t, cache, req)
		wantHits(t, srv, 9)
	})
}

func TestIncompleteResponseNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.3-no-incomplete-use")

	synctest.Test(t, func(t *testing.T) {
		// The body ends before its Content-Length.
		cache, srv := newTestCache(t, respond(200, "hel", hdrCacheControl, ccMaxAge60, hdrContentLength, "5"))
		get(t, cache, testURL)
		get(t, cache, testURL)
		wantHits(t, srv, 2)

		// The caller stops reading.
		cache, srv = newTestCache(t, respond(200, bodyHello, hdrCacheControl, ccMaxAge60))

		res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
		if err != nil {
			t.Fatal(err)
		}

		_, _ = res.Body.Read(make([]byte, 2))
		_ = res.Body.Close()

		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestMaxBodySize(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		for _, test := range []struct {
			fields []string
			hits   int
		}{
			{[]string{hdrContentLength, "5"}, 2},
			{nil, 2},
			{[]string{hdrContentLength, "0"}, 1},
		} {
			body := bodyHello
			if len(test.fields) > 0 && test.fields[1] == "0" {
				body = ""
			}

			cache, srv := newTestCache(t, respond(200, body, append(test.fields, hdrCacheControl, ccMaxAge60)...),
				WithMaxBodySize(4))
			if _, got := get(t, cache, testURL); got != body {
				t.Errorf("%q: body = %q", test.fields, got)
			}

			get(t, cache, testURL)
			wantHits(t, srv, test.hits)
		}
	})
}

func TestEmptyBodyStoredWithoutRead(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(204, "", hdrCacheControl, ccMaxAge60, hdrContentLength, "0"))

		first, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
		if err != nil {
			t.Fatal(err)
		}

		_ = first.Body.Close()
		res, _ := get(t, cache, testURL)
		wantHits(t, srv, 1)

		if res.StatusCode != http.StatusNoContent {
			t.Errorf("status %d, want 204", res.StatusCode)
		}
	})
}

func TestDate(t *testing.T) {
	t.Parallel()

	covers(t,
		"9110-6.6.1-add-date",
		"9110-6.6.1-date-approx",
		"9110-6.6.1-invalid-date",
		"9110-5.6.7-imf-fixdate",
		"9110-5.6.7-no-whitespace",
	)

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(200, ""))
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			res, _ := roundTrip(t, cache, newRequest(method, testURL))
			if got, want := res.Header.Get(hdrDate), formatHTTPDate(time.Now()); got != want {
				t.Errorf("%s: Date = %q, want %q", method, got, want)
			}
		}

		if formatHTTPDate(time.Now()) != "Sat, 01 Jan 2000 00:00:00 GMT" {
			t.Errorf("formatHTTPDate = %q", formatHTTPDate(time.Now()))
		}
	})

	synctest.Test(t, func(t *testing.T) {
		// An invalid Date passes through, and is replaced when stored.
		cache, _ := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60, hdrDate, "yesterday"))
		res, _ := get(t, cache, testURL)
		wantHeader(t, res, hdrDate, "yesterday")

		received := formatHTTPDate(time.Now())

		time.Sleep(time.Second)

		res, _ = get(t, cache, testURL)
		wantHeader(t, res, hdrDate, received)
		wantHeader(t, res, hdrAge, "1")
	})
}

func TestForwardedUnchanged(t *testing.T) {
	t.Parallel()

	covers(t, "9110-7.7-host-name", "9110-7.7-path-query", "9110-7.7-metadata", "9111-5.2-pass-through")

	synctest.Test(t, func(t *testing.T) {
		resFields := []string{
			hdrCacheControl, "max-age=1, community=\"x\"",
			hdrContentType, typePlain,
			hdrDate, formatHTTPDate(time.Now()),
			hdrETag, etagA,
			"Server", "origin/1.0",
			"Via", "1.1 upstream",
			"X-Custom", "1",
		}
		cache, srv := newTestCache(t, respond(200, bodyText, resFields...))

		const rawURL = "http://Example.com/a%2Fb/./c?y=%20&x=1"

		reqFields := []string{
			hdrCacheControl, "max-age=5, x-ext=\"1\"",
			"Pragma", ccNoCache,
			"Via", "1.1 client",
			"X-Forwarded-For", "192.0.2.1",
		}
		req := newRequest(http.MethodGet, rawURL, reqFields...)
		req.Host = "example.com.:80"

		res, _ := roundTrip(t, cache, req)

		sent := srv.last()
		if sent.URL.String() != rawURL || sent.Host != req.Host {
			t.Errorf("origin got %s with Host %q", sent.URL, sent.Host)
		}

		for name := range pairs(reqFields) {
			if got := sent.Header.Values(name); !slices.Equal(got, req.Header.Values(name)) {
				t.Errorf("origin got %s %q", name, got)
			}
		}

		for name, value := range pairs(resFields) {
			wantHeader(t, res, name, value)
		}

		// A validation request only adds preconditions.
		time.Sleep(2 * time.Second)

		req = newRequest(http.MethodGet, rawURL, reqFields...)
		req.Host = "example.com.:80"
		roundTrip(t, cache, req)

		sent = srv.last()
		if len(sent.Header) != len(req.Header)+1 || sent.Header.Get(hdrIfNoneMatch) != etagA {
			t.Errorf("validation request header = %v", sent.Header)
		}

		if req.Header.Get(hdrIfNoneMatch) != "" {
			t.Error("the caller's request was modified")
		}
	})
}

func TestContentNotTransformed(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.2.6-no-transform", "9110-7.7-no-transform")

	body := string([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, '\r', '\n', 0x80})

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, body, hdrCacheControl, "max-age=60, no-transform",
			hdrContentEncoding, "gzip", hdrContentType, "application/octet-stream"))
		get(t, cache, testURL)

		res, got := get(t, cache, testURL)
		wantHits(t, srv, 1)

		if got != body {
			t.Errorf("body = %q, want %q", got, body)
		}

		wantHeader(t, res, hdrContentEncoding, "gzip")
		wantHeader(t, res, hdrContentType, "application/octet-stream")
	})
}

func TestTrailersNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3.1-trailers-store", "9111-3.1-trailers-merge")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Trailer", "X-Checksum")
			writer.Header().Set(hdrCacheControl, ccMaxAge60)
			_, _ = io.WriteString(writer, bodyText)
			writer.Header().Set("X-Checksum", "abc")
		})

		first, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
		if err != nil {
			t.Fatal(err)
		}

		_, _ = io.ReadAll(first.Body)
		_ = first.Body.Close()

		if first.Trailer.Get("X-Checksum") != "abc" {
			t.Errorf("trailer didn't pass through: %v", first.Trailer)
		}

		res, _ := get(t, cache, testURL)
		wantHits(t, srv, 1)
		wantHeader(t, res, "X-Checksum", "")

		if len(res.Trailer) != 0 {
			t.Errorf("stored response has trailers %v", res.Trailer)
		}
	})
}

func TestInvalidationAcrossServers(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// A proxy sends requests for one target URI to two backends.
	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodPost {
				respond(204, "")(writer, req)

				return
			}

			respond(200, html.EscapeString(req.URL.Host), hdrCacheControl, ccMaxAge60)(writer, req)
		})

		send := func(method, server string) string {
			req := newRequest(method, "http://"+server+"/r")
			req.Host = hostExample
			_, body := roundTrip(t, cache, req)

			return body
		}

		// Each backend's response answers only requests sent to it.
		for _, server := range []string{hostBackend, hostBackend2, hostBackend, hostBackend2} {
			if body := send(http.MethodGet, server); body != server {
				t.Errorf("GET via %s: body %q", server, body)
			}
		}

		wantHits(t, srv, 2)

		// A POST through one backend invalidates the target URI for both.
		send(http.MethodPost, hostBackend)
		send(http.MethodGet, hostBackend2)
		wantHits(t, srv, 4)
	})
}

func TestRevalidationAcrossServers(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update")

	// A proxy sends requests for one target URI to two backends, and a 304
	// through one of them updates only that backend's response.
	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Header.Get(hdrIfNoneMatch) == etagA {
				respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)

				return
			}

			respond(http.StatusOK, html.EscapeString(req.URL.Host), hdrCacheControl, ccMaxAge1, hdrETag, etagA)(writer, req)
		})

		send := func(server string) {
			req := newRequest(http.MethodGet, "http://"+server+"/r")
			req.Host = hostExample
			roundTrip(t, cache, req)
		}

		send(hostBackend)
		send(hostBackend2)
		time.Sleep(2 * time.Second)

		for _, step := range []struct {
			server string
			hits   int
		}{{hostBackend, 3}, {hostBackend, 3}, {hostBackend2, 4}} {
			send(step.server)
			wantHits(t, srv, step.hits)
		}

		// The second backend's response is still stored, and revalidated.
		if got := srv.last().Header.Get(hdrIfNoneMatch); got != etagA {
			t.Errorf("request via the second backend: If-None-Match %q, want %q", got, etagA)
		}
	})
}

func TestManyServers(t *testing.T) {
	t.Parallel()

	// A proxy round-robins one Host over more servers than defaultMaxVariants.
	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			respond(200, html.EscapeString(req.URL.Host), hdrCacheControl, "max-age=600")(writer, req)
		})

		for i := range 3 * (defaultMaxVariants + 1) {
			server := "10.0.0." + strconv.Itoa(i%(defaultMaxVariants+1))
			req := newRequest(http.MethodGet, "http://"+server+"/r")

			req.Host = hostExample
			if _, body := roundTrip(t, cache, req); body != server {
				t.Fatalf("GET via %s: body %q", server, body)
			}
		}

		wantHits(t, srv, defaultMaxVariants+1)
	})
}

func TestMaxVariants(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		handler := respond(http.StatusOK, bodyText, hdrCacheControl, "max-age=600", "Vary", hdrAccept)

		// Past the limit, the oldest response is evicted: after a, b and c,
		// c and b are hits, and a goes to the origin again.
		cache, srv := newTestCache(t, handler, WithMaxVariants(2))
		for _, step := range []struct {
			accept string
			hits   int
		}{{"a", 1}, {"b", 2}, {"c", 3}, {"c", 3}, {"b", 3}, {"a", 4}} {
			get(t, cache, testURL, hdrAccept, step.accept)
			wantHits(t, srv, step.hits)
			time.Sleep(time.Second)
		}

		// With no practical limit, every response is kept.
		cache, srv = newTestCache(t, handler, WithMaxVariants(math.MaxInt))

		for range 2 {
			for i := range 3 * defaultMaxVariants {
				get(t, cache, testURL, hdrAccept, strconv.Itoa(i))
			}
		}

		wantHits(t, srv, 3*defaultMaxVariants)
	})
}

func TestMaxBytes(t *testing.T) {
	t.Parallel()

	handler := respond(http.StatusOK, strings.Repeat("x", 1000), hdrCacheControl, ccMaxAge60)

	probe, _ := newTestCache(t, handler)
	get(t, probe, testURL)

	stored, _ := probe.entries.Get(testURL)
	size := weigh(testURL, stored)

	// With room for three responses, storing a fourth evicts the first: b, c
	// and d are hits, and a goes to the origin again.
	cache, srv := newTestCache(t, handler, WithMaxBytes(int64(3*size)))
	for _, path := range []string{"a", "b", "c", "d"} {
		get(t, cache, testURL+path)
	}

	for step, path := range []string{"b", "c", "d", "a"} {
		get(t, cache, testURL+path)
		wantHits(t, srv, 4+step/3)
	}
}

func TestMaxBytesVariants(t *testing.T) {
	t.Parallel()

	// One response fits and two don't, so a target URI keeps only the newest.
	handler := respond(http.StatusOK, strings.Repeat("x", 600), hdrCacheControl, ccMaxAge60, "Vary", hdrAccept)

	cache, srv := newTestCache(t, handler, WithMaxBytes(1000))
	for _, step := range []struct {
		accept string
		hits   int
	}{{"a", 1}, {"b", 2}, {"b", 2}, {"a", 3}, {"a", 3}, {"b", 4}} {
		get(t, cache, testURL, hdrAccept, step.accept)
		wantHits(t, srv, step.hits)
	}
}

func TestMaxBytesTooLarge(t *testing.T) {
	t.Parallel()

	// A response too large to store doesn't take the place of the one stored
	// for Accept small.
	cache, srv := newTestCache(t, sizedByAccept, WithMaxBytes(1000), WithMaxVariants(1))
	get(t, cache, testURL, hdrAccept, "small")
	get(t, cache, testURL, hdrAccept, "big")
	get(t, cache, testURL, hdrAccept, "small")
	wantHits(t, srv, 2)
}

func TestMaxBytesUpdate(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// The origin answers a conditional request with a 304 that adds a
		// field of padding bytes.
		padding := 0
		cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Header.Get(hdrIfNoneMatch) != "" {
				respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge1, hdrETag, etagA,
					hdrFoo, strings.Repeat("x", padding))(writer, req)

				return
			}

			respond(http.StatusOK, strings.Repeat("x", 400), hdrCacheControl, ccMaxAge1, hdrETag, etagA,
				"Vary", hdrAccept)(writer, req)
		}, WithMaxBytes(1100))

		stored := func() []string {
			var accepts []string

			if ent, found := cache.entries.Get(testURL); found {
				for _, response := range ent.variants {
					accepts = append(accepts, response.vary[0].value)
				}
			}

			return accepts
		}

		get(t, cache, testURL, hdrAccept, "a")
		time.Sleep(time.Second)
		get(t, cache, testURL, hdrAccept, "b")
		time.Sleep(2 * time.Second)

		// A 304 that makes a's response larger drops the older one for b to
		// make room.
		padding = 200

		if _, body := get(t, cache, testURL, hdrAccept, "a"); len(body) != 400 || !slices.Equal(stored(), []string{"a"}) {
			t.Errorf("after a larger update, body %d bytes, stored %q, want a", len(body), stored())
		}

		// One that makes it too large to store removes it.
		time.Sleep(2 * time.Second)

		padding = 1000

		get(t, cache, testURL, hdrAccept, "a")

		if _, found := cache.entries.Get(testURL); found {
			t.Errorf("after a too large update, stored %q, want no entry", stored())
		}
	})
}

func TestInvalidatedSince(t *testing.T) {
	t.Parallel()

	var shard stripe

	invalidate := shard.record

	invalidate("a")

	if !shard.invalidatedSince("a", 0) || shard.invalidatedSince("b", 0) || shard.invalidatedSince("a", 1) {
		t.Error("after invalidating a: wrong result")
	}

	for range recentInvalidations - 1 {
		invalidate("c")
	}

	if shard.invalidatedSince("b", 0) {
		t.Error("b reported invalidated with every invalidation still recorded")
	}

	// One more, and invalidation 1 is no longer recorded.
	invalidate("c")

	if !shard.invalidatedSince("b", 0) {
		t.Error("b not reported invalidated after the record overflowed")
	}

	if shard.invalidatedSince("b", 1) {
		t.Error("b reported invalidated with every invalidation since 1 recorded")
	}
}

func TestUnrelatedInvalidationKeepsStore(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, bodyText, hdrCacheControl, ccMaxAge60))

		// Find another URI whose key is on the same stripe as testURL's.
		tgt, _ := newTarget(newRequest(http.MethodGet, testURL))

		var other string
		for i := 0; other == ""; i++ {
			path := "/other" + strconv.Itoa(i)
			if cache.stripe(tgt.key(path)) == cache.stripe(tgt.key("/r")) {
				other = "http://example.com" + path
			}
		}

		res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
		if err != nil {
			t.Fatal(err)
		}

		roundTrip(t, cache, newRequest(http.MethodPost, other))

		_, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}

		_ = res.Body.Close()

		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}
