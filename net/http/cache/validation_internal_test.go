package cache

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestValidation(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-4.3.1-etag",
		"9111-4.3.1-ims",
		"9110-13.1.2-client-inm",
		"9111-4.3.4-update",
		"9111-3.2-update",
	)

	synctest.Test(t, func(t *testing.T) {
		lastMod := formatHTTPDate(time.Now().Add(-time.Hour))
		cache, srv := newTestCache(t, sequence(
			respond(200, bodyText, hdrCacheControl, ccMaxAge1, hdrETag, etagV1, hdrLastModified, lastMod,
				hdrContentType, typePlain, "X-Old", "1"),
			respond(304, "", hdrCacheControl, "max-age=100", hdrETag, etagV1, "X-New", "1"),
		))

		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		res, body := get(t, cache, testURL)
		wantHits(t, srv, 2)

		sent := srv.last()
		if inm, ims := sent.Header.Get(hdrIfNoneMatch), sent.Header.Get(hdrIfModifiedSince); inm != etagV1 || ims != lastMod {
			t.Errorf("validation request has If-None-Match %q and If-Modified-Since %q", inm, ims)
		}

		// The 304 completes the request with the updated stored response.
		if res.StatusCode != http.StatusOK || body != bodyText {
			t.Errorf("got %d %q, want the stored 200", res.StatusCode, body)
		}

		wantHeader(t, res, hdrCacheControl, "max-age=100")
		wantHeader(t, res, "X-New", "1")
		wantHeader(t, res, "X-Old", "1")
		wantHeader(t, res, hdrContentType, typePlain)
		// The origin was just contacted, so the response has no Age.
		wantHeader(t, res, hdrAge, "")

		time.Sleep(50 * time.Second)

		res, body = get(t, cache, testURL)
		wantHits(t, srv, 2)

		if body != bodyText {
			t.Errorf("body = %q after update", body)
		}

		wantHeader(t, res, hdrAge, "50")
	})
}

func TestValidationNoMatch(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-strong")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(200, "v1", hdrCacheControl, ccMaxAge1, hdrETag, etagV1),
			// A 304 for a different representation.
			respond(304, "", hdrCacheControl, "max-age=100", hdrETag, `"v2"`),
			respond(200, "v2", hdrCacheControl, "max-age=100", hdrETag, `"v2"`),
		))

		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		// The 304 can't update v1, so the cache asks again without
		// validators.
		res, body := get(t, cache, testURL)
		wantHits(t, srv, 3)

		if res.StatusCode != http.StatusOK || body != "v2" {
			t.Errorf("got %d %q, want the new full response", res.StatusCode, body)
		}

		if got := srv.last().Header.Get(hdrIfNoneMatch); got != "" {
			t.Errorf("retry has If-None-Match %q", got)
		}

		if _, body := get(t, cache, testURL); body != "v2" {
			t.Errorf("stored body = %q, want v2", body)
		}

		wantHits(t, srv, 3)
	})
}

func TestValidationNotModifiedWithoutValidators(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update")

	synctest.Test(t, func(t *testing.T) {
		// The 304 omits the ETag, but answers the cache's If-None-Match.
		cache, srv := newTestCache(t, sequence(
			respond(200, "v1", hdrCacheControl, ccMaxAge1, hdrETag, etagV1),
			respond(304, "", hdrCacheControl, "max-age=100"),
		))

		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		res, body := get(t, cache, testURL)
		wantHits(t, srv, 2)

		if res.StatusCode != http.StatusOK || body != "v1" {
			t.Errorf("got %d %q, want the validated stored response", res.StatusCode, body)
		}

		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestFullResponseToValidation(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.3-full", "9111-4.3.3-store-full")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(200, "v1", hdrCacheControl, ccMaxAge1, hdrETag, etagV1),
			respond(200, "v2", hdrCacheControl, "max-age=100", hdrETag, `"v2"`),
		))

		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		if _, body := get(t, cache, testURL); body != "v2" {
			t.Errorf("body = %q, want the full response", body)
		}

		if _, body := get(t, cache, testURL); body != "v2" {
			t.Errorf("stored body = %q, want v2", body)
		}

		wantHits(t, srv, 2)
	})
}

// headHandler answers a HEAD request with the ETag etag, and a GET request
// with a response that is stale after a second, with the ETag "a".
func headHandler(etag string) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodHead {
			respond(200, "", hdrCacheControl, "max-age=100", hdrETag, etag, hdrContentLength, "4", "X-Head", "1")(writer, req)

			return
		}

		respond(200, bodyText, hdrCacheControl, ccMaxAge1, hdrETag, etagA, hdrContentLength, "4")(writer, req)
	}
}

func TestHEADUpdatesStoredResponse(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.5-head", "9111-4.3.5-update", "9111-4.3.5-head-fields", "9111-4.3.5-stale")

	// A HEAD response without validators is compared by Content-Length only.
	for _, etag := range []string{etagA, ""} {
		t.Run(etag, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, headHandler(etag))
				get(t, cache, testURL)
				time.Sleep(2 * time.Second)

				roundTrip(t, cache, newRequest(http.MethodHead, testURL))
				wantHits(t, srv, 2)

				// The HEAD response refreshed the stored GET response.
				res, body := get(t, cache, testURL)
				wantHits(t, srv, 2)

				if body != bodyText {
					t.Errorf("ETag %q: body = %q", etag, body)
				}

				wantHeader(t, res, "X-Head", "1")
				wantHeader(t, res, hdrCacheControl, "max-age=100")
			})
		})
	}
}

// The bodies of a resource before and after a POST changes it, of the same
// length.
const (
	bodyOld = "old"
	bodyNew = "new"
)

// changingOrigin answers GET with bodyOld and ETag "1" until a POST changes
// them to bodyNew and "2", and answers If-None-Match itself. Both bodies have
// the same length. Its HEAD responses have no validator, as from a handler
// that computes them while writing the body, and a Content-Length only if
// length is set.
func changingOrigin(changed *atomic.Bool, length bool) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		body, tag := bodyOld, `"1"`
		if changed.Load() {
			body, tag = bodyNew, `"2"`
		}

		switch {
		case req.Method == http.MethodPost:
			changed.Store(true)
			respond(http.StatusNoContent, "")(writer, req)
		case req.Method == http.MethodHead && length:
			respond(http.StatusOK, "", hdrCacheControl, ccMaxAge60, hdrContentLength, strconv.Itoa(len(body)))(writer, req)
		case req.Method == http.MethodHead:
			respond(http.StatusOK, "", hdrCacheControl, ccMaxAge60)(writer, req)
		case req.Header.Get(hdrIfNoneMatch) == tag:
			respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, tag)(writer, req)
		default:
			respond(http.StatusOK, body, hdrCacheControl, ccMaxAge60, hdrETag, tag,
				hdrContentLength, strconv.Itoa(len(body)))(writer, req)
		}
	}
}

func TestHEADWithoutValidatorKeepsInvalid(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.5-stale", "9111-4.4-target")

	// A stored response that must be validated, after a POST or Load, stays
	// so after a HEAD response with nothing to compare but Content-Length.
	for _, test := range []struct {
		name         string
		length, load bool
	}{{"POST", false, false}, {"POST, Content-Length", true, false}, {"Load", false, true}} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var changed atomic.Bool

			handler := changingOrigin(&changed, test.length)

			cache, _ := newTestCache(t, handler)
			get(t, cache, testURL)

			if test.load {
				snapshot := snapshotOf(t, cache)

				changed.Store(true)

				cache, _ = loadSnapshot(t, snapshot, handler)
			} else {
				roundTrip(t, cache, newRequest(http.MethodPost, testURL))
			}

			roundTrip(t, cache, newRequest(http.MethodHead, testURL))

			if _, body := get(t, cache, testURL); body != bodyNew {
				t.Errorf("GET after HEAD: body %q, want the origin's new one", body)
			}
		})
	}
}

func TestClientNotModifiedKeepsInvalid(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// A 304 without validators, to a client's own If-Modified-Since, says
	// nothing about a stored response without validators that a POST
	// invalidated.
	var changed atomic.Bool

	cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
		body := bodyOld
		if changed.Load() {
			body = bodyNew
		}

		switch {
		case req.Method == http.MethodPost:
			changed.Store(true)
			respond(http.StatusNoContent, "")(writer, req)
		case req.Header.Get(hdrIfModifiedSince) != "":
			respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60)(writer, req)
		default:
			respond(http.StatusOK, body, hdrCacheControl, ccMaxAge60)(writer, req)
		}
	})

	get(t, cache, testURL)
	roundTrip(t, cache, newRequest(http.MethodPost, testURL))

	if res, _ := get(t, cache, testURL, hdrIfModifiedSince, dateIMF); res.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET: status %d, want the origin's 304", res.StatusCode)
	}

	if _, body := get(t, cache, testURL); body != bodyNew {
		t.Errorf("GET after the 304: body %q, want the origin's new one", body)
	}
}

func TestClientNotModifiedWithValidatorUpdates(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update")

	// A 304 whose ETag matches, to a client's own If-None-Match, makes a stored
	// response that a POST invalidated usable again.
	cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost:
			respond(http.StatusNoContent, "")(writer, req)
		case req.Header.Get(hdrIfNoneMatch) == etagA:
			respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
		default:
			respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
		}
	})

	get(t, cache, testURL)
	roundTrip(t, cache, newRequest(http.MethodPost, testURL))
	get(t, cache, testURL, hdrIfNoneMatch, etagA)

	if _, body := get(t, cache, testURL); body != bodyText {
		t.Errorf("GET after the 304: body %q, want %q", body, bodyText)
	}

	wantHits(t, srv, 3)
}

func TestOwnNotModifiedUpdatesLoaded(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update")

	// A 304 without validators, to the cache's own conditional request for a
	// loaded response, makes that response usable.
	handler := func(writer http.ResponseWriter, req *http.Request) {
		if req.Header.Get(hdrIfNoneMatch) == etagA {
			respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60)(writer, req)

			return
		}

		respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
	}

	cache, _ := newTestCache(t, handler)
	get(t, cache, testURL)

	restored, srv := loadSnapshot(t, snapshotOf(t, cache), handler)
	for range 2 {
		if _, body := get(t, restored, testURL); body != bodyText {
			t.Errorf("GET: body %q, want %q", body, bodyText)
		}
	}

	wantHits(t, srv, 1)

	if got := srv.last().Header.Get(hdrIfNoneMatch); got != etagA {
		t.Errorf("request to the origin: If-None-Match %q, want %q", got, etagA)
	}
}

func TestHEADWithValidatorUpdatesLoaded(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.5-update")

	// A HEAD response whose ETag matches makes a loaded response usable
	// without fetching it again.
	handler := func(writer http.ResponseWriter, req *http.Request) {
		body := bodyText
		if req.Method == http.MethodHead {
			body = ""
		}

		respond(http.StatusOK, body, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
	}

	cache, _ := newTestCache(t, handler)
	get(t, cache, testURL)

	restored, srv := loadSnapshot(t, snapshotOf(t, cache), handler)
	roundTrip(t, restored, newRequest(http.MethodHead, testURL))

	if _, body := get(t, restored, testURL); body != bodyText {
		t.Errorf("GET after HEAD: body %q, want %q", body, bodyText)
	}

	wantHits(t, srv, 1)
}

func TestHEADWithOtherETagMakesStale(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.5-stale")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, headHandler(etagB))
		get(t, cache, testURL)
		roundTrip(t, cache, newRequest(http.MethodHead, testURL, hdrCacheControl, ccNoCache))

		// A different ETag makes the stored response stale.
		get(t, cache, testURL)
		wantHits(t, srv, 3)
	})
}

func TestHEADWithoutStoredContentLength(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.5-stale")

	synctest.Test(t, func(t *testing.T) {
		// A stored response without Content-Length can't be compared.
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodHead {
				respond(200, "", hdrCacheControl, "max-age=100", hdrETag, etagA, hdrContentLength, "4")(writer, req)

				return
			}

			respond(200, bodyText, hdrCacheControl, "max-age=100", hdrETag, etagA)(writer, req)
		})
		get(t, cache, testURL)
		roundTrip(t, cache, newRequest(http.MethodHead, testURL, hdrCacheControl, ccNoCache))
		get(t, cache, testURL)
		wantHits(t, srv, 3)
	})
}

// wantNotModified checks that the 304 response res, with the body body, to a
// request with the header fields fields, has the fields RFC 9110 requires
// and no other representation metadata.
func wantNotModified(tb testing.TB, fields []string, res reply, body string) {
	tb.Helper()

	if body != "" {
		tb.Errorf("%q: 304 has body %q", fields, body)
	}

	for _, name := range []string{hdrCacheControl, "Content-Location", hdrDate, hdrETag, hdrExpires, "Vary", hdrAge} {
		if res.Header.Get(name) == "" {
			tb.Errorf("%q: 304 lacks %s", fields, name)
		}
	}

	for _, name := range []string{hdrContentType, hdrLastModified, "X-Other"} {
		if value := res.Header.Get(name); value != "" {
			tb.Errorf("%q: 304 has %s: %q", fields, name, value)
		}
	}
}

// preconditionCase is the header fields of a client's request, and the
// status the cache answers it with.
type preconditionCase struct {
	fields []string
	status int
}

// preconditionCases returns the requests to a stored response that was last
// modified at lastMod, and the status the cache answers each with. The
// request header fields refer to the HTTP-dates before, which is earlier than
// lastMod, and now.
func preconditionCases(lastMod, before, now string) []preconditionCase {
	return []preconditionCase{
		{[]string{hdrIfNoneMatch, etagA}, 304},
		{[]string{hdrIfNoneMatch, `W/"a"`}, 304},
		{[]string{hdrIfNoneMatch, `"b", "a"`}, 304},
		{[]string{hdrIfNoneMatch, etagB, hdrIfNoneMatch, etagA}, 304},
		{[]string{hdrIfNoneMatch, "*"}, 304},
		{[]string{hdrIfNoneMatch, etagB}, 200},
		{[]string{hdrIfNoneMatch, `a`}, 200},
		{[]string{hdrIfNoneMatch, etagB, hdrIfModifiedSince, lastMod}, 200},
		{[]string{hdrIfModifiedSince, lastMod}, 304},
		{[]string{hdrIfModifiedSince, now}, 304},
		{[]string{hdrIfModifiedSince, before}, 200},
		{[]string{hdrIfModifiedSince, "yesterday"}, 200},
		{[]string{hdrIfModifiedSince, lastMod, hdrIfModifiedSince, lastMod}, 200},
	}
}

func TestClientPreconditions(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-4.3.2-evaluate",
		"9110-13.2.1-evaluate",
		"9110-13.1.2-weak",
		"9110-13.1.3-ims-inm",
		"9110-13.1.3-ims-invalid",
		"9110-13.1.3-ims-list",
		"9110-13.2.2-order",
		"9110-15.4.5-generate",
		"9110-15.4.5-metadata",
	)

	synctest.Test(t, func(t *testing.T) {
		lastMod := formatHTTPDate(time.Now().Add(-time.Hour))
		before := formatHTTPDate(time.Now().Add(-2 * time.Hour))
		cache, srv := newTestCache(t, respond(200, bodyText, hdrCacheControl, "max-age=100", hdrETag, etagA,
			hdrLastModified, lastMod, hdrContentType, typePlain, "Content-Location", "/r.txt",
			"Vary", hdrAccept, hdrExpires, formatHTTPDate(time.Now().Add(time.Hour)), "X-Other", "1"))
		get(t, cache, testURL)
		time.Sleep(time.Second)

		for _, test := range preconditionCases(lastMod, before, formatHTTPDate(time.Now())) {
			res, body := get(t, cache, testURL, test.fields...)
			if res.StatusCode != test.status {
				t.Errorf("%q: status %d, want %d", test.fields, res.StatusCode, test.status)

				continue
			}

			if test.status == 200 {
				if body != bodyText {
					t.Errorf("%q: body %q", test.fields, body)
				}

				continue
			}

			wantNotModified(t, test.fields, res, body)
		}

		wantHits(t, srv, 1)
	})
}

func TestClientPreconditionsWithoutLastModified(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.2-ims-date", "9110-13.1.3-origin-clock", "9110-13.2.1-non-2xx", "9110-13.1.2-weak")

	synctest.Test(t, func(t *testing.T) {
		// The origin's clock is an hour fast. If-Modified-Since is compared
		// with its Date, not with the cache's clock.
		date := time.Now().Add(time.Hour)
		cache, srv := newTestCache(t, respond(200, bodyText, hdrCacheControl, "max-age=100", hdrDate, formatHTTPDate(date)))
		get(t, cache, testURL)

		res, _ := get(t, cache, testURL, hdrIfModifiedSince, formatHTTPDate(date))
		if res.StatusCode != http.StatusNotModified {
			t.Errorf("If-Modified-Since = Date: status %d, want 304", res.StatusCode)
		}

		// The 304 doesn't invent a Last-Modified the stored response lacks.
		wantHeader(t, res, hdrLastModified, "")

		res, _ = get(t, cache, testURL, hdrIfModifiedSince, formatHTTPDate(date.Add(-time.Second)))
		if res.StatusCode != http.StatusOK {
			t.Errorf("If-Modified-Since before Date: status %d, want 200", res.StatusCode)
		}

		// "*" matches any current representation, with or without an ETag.
		res, _ = get(t, cache, testURL, hdrIfNoneMatch, "*")
		if res.StatusCode != http.StatusNotModified {
			t.Errorf("If-None-Match: *: status %d, want 304", res.StatusCode)
		}

		wantHits(t, srv, 1)
	})

	synctest.Test(t, func(t *testing.T) {
		// Preconditions don't apply to a stored 404.
		cache, srv := newTestCache(t, respond(404, "missing", hdrCacheControl, "max-age=100", hdrETag, etagA))
		get(t, cache, testURL)

		res, body := get(t, cache, testURL, hdrIfNoneMatch, etagA)
		if res.StatusCode != http.StatusNotFound || body != "missing" {
			t.Errorf("got %d %q, want the stored 404", res.StatusCode, body)
		}

		wantHits(t, srv, 1)
	})
}

func TestPreconditionsForwarded(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-4.3.2-origin-only",
		"9111-4.3.2-unsatisfiable",
		"9111-4.3.2-no-stored",
		"9110-13.1.1-ignore",
		"9110-13.1.4-ignore",
		"9110-13.1.3-ims-method",
		"9110-13.2.1-no-eval",
		"9110-13.2.1-forward",
		"9110-15.4.5-forward",
	)

	synctest.Test(t, func(t *testing.T) {
		lastMod := formatHTTPDate(time.Now().Add(-time.Hour))
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Header.Get(hdrIfNoneMatch) == etagA {
				respond(304, "", hdrETag, etagA)(writer, req)

				return
			}

			respond(200, bodyText, hdrCacheControl, "max-age=100", hdrETag, etagA, hdrLastModified, lastMod)(writer, req)
		})

		// With nothing stored, the precondition goes to the origin, and so
		// does its 304.
		res, _ := get(t, cache, testURL, hdrIfNoneMatch, etagA)
		wantHits(t, srv, 1)

		if res.StatusCode != http.StatusNotModified {
			t.Errorf("status %d, want the origin's 304", res.StatusCode)
		}

		get(t, cache, testURL)
		wantHits(t, srv, 2)

		for idx, fields := range [][]string{
			{"If-Match", etagA},
			{"If-Unmodified-Since", lastMod},
			// no-cache means the stored response can't satisfy the request.
			{hdrIfNoneMatch, etagA, hdrCacheControl, ccNoCache},
		} {
			get(t, cache, testURL, fields...)
			wantHits(t, srv, 3+idx)

			sent := srv.last()
			for j := 0; j < len(fields); j += 2 {
				if got := sent.Header.Get(fields[j]); got != fields[j+1] {
					t.Errorf("%q: origin got %s %q", fields, fields[j], got)
				}
			}
		}

		// If-Modified-Since only applies to GET and HEAD.
		roundTrip(t, cache, newRequest(http.MethodPost, testURL, hdrIfModifiedSince, lastMod))
		wantHits(t, srv, 6)

		if got := srv.last().Header.Get(hdrIfModifiedSince); got != lastMod {
			t.Errorf("POST: origin got If-Modified-Since %q", got)
		}
	})
}

func TestClientNotModifiedUpdatesStore(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update", "9110-15.4.5-forward")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(200, bodyText, hdrCacheControl, ccMaxAge1),
			respond(304, "", hdrCacheControl, "max-age=100"),
		))
		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		// A client's own If-Modified-Since, not derived from a stored
		// validator, gets a 304 without validators. It updates the lone
		// stored response, which has none either.
		res, _ := get(t, cache, testURL, hdrIfModifiedSince, formatHTTPDate(time.Now()))
		if res.StatusCode != http.StatusNotModified {
			t.Errorf("status %d, want the origin's 304", res.StatusCode)
		}

		res, body := get(t, cache, testURL)
		wantHits(t, srv, 2)

		if res.StatusCode != http.StatusOK || body != bodyText {
			t.Errorf("got %d %q, want the updated stored response", res.StatusCode, body)
		}
	})
}

// updateRuleCase is a 304 or HEAD response that updates a stored response,
// the request that provokes it, and whether the cache is shared.
type updateRuleCase struct {
	name   string
	shared bool
	fresh  bool // revalidate before the stored response is stale
	method string
	fields []string // of the revalidating request
	update []string // of the 304 or HEAD response
}

func updateRuleCases() []updateRuleCase {
	return []updateRuleCase{
		{"304 with no-store", false, false, http.MethodGet, nil, []string{hdrCacheControl, ccNoStoreMaxAge600}},
		{"304 with no-store to a fresh response", false, true, http.MethodGet,
			[]string{hdrCacheControl, ccNoCache}, []string{hdrCacheControl, ccNoStoreMaxAge600}},
		{"304 to the client's conditional with no-store", false, false, http.MethodGet,
			[]string{hdrIfNoneMatch, etagV1}, []string{hdrCacheControl, ccNoStoreMaxAge600}},
		{"HEAD with no-store", false, false, http.MethodHead, nil, []string{hdrCacheControl, ccNoStoreMaxAge600}},
		{"304 with private in a shared cache", true, false, http.MethodGet, nil,
			[]string{hdrCacheControl, "private, max-age=600", hdrSetCookie, cookieSecret}},
		{"HEAD with private in a shared cache", true, false, http.MethodHead, nil,
			[]string{hdrCacheControl, "private, max-age=600", hdrSetCookie, cookieSecret}},
		{"304 to Authorization in a shared cache", true, false, http.MethodGet, []string{hdrAuthorization, "Bearer x"},
			[]string{hdrCacheControl, "max-age=600", hdrSetCookie, cookieSecret}},
	}
}

func TestUpdatesFollowStorageRules(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-3-no-store",
		"9111-3-shared-private",
		"9111-3-shared-auth",
		"9111-3.5-authorization",
		"9111-5.2.2.5-no-store",
		"9111-5.2.2.5-no-reuse",
		"9111-5.2.2.7-shared",
	)

	for _, test := range updateRuleCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var opts []Option
				if test.shared {
					opts = append(opts, WithShared())
				}

				update := append([]string{hdrETag, etagV1, hdrContentLength, "2"}, test.update...)

				status := http.StatusNotModified
				if test.method == http.MethodHead {
					status = http.StatusOK
				}

				cache, srv := newTestCache(t, sequence(
					respond(200, "v1", hdrCacheControl, "public, max-age=10", hdrETag, etagV1, hdrContentLength, "2"),
					respond(status, "", update...),
					respond(200, "v1", hdrCacheControl, "public, max-age=60", hdrETag, etagV1, hdrContentLength, "2"),
				), opts...)

				get(t, cache, testURL)

				if !test.fresh {
					time.Sleep(11 * time.Second)
				}

				roundTrip(t, cache, newRequest(test.method, testURL, test.fields...))
				wantHits(t, srv, 2)

				// The update wasn't stored, and the stored response it would
				// have updated must be validated before reuse.
				res, body := get(t, cache, testURL)
				if n := srv.hits(); n != 3 || body != "v1" {
					t.Errorf("%s: origin received %d requests and body is %q, want 3 and v1", test.name, n, body)
				}

				wantHeader(t, res, hdrSetCookie, "")
				wantHeader(t, res, hdrCacheControl, "public, max-age=60")
			})
		})
	}
}

func TestHEADValidatedByNotModified(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-update", "9110-9.3.2-no-content")

	synctest.Test(t, func(t *testing.T) {
		// The cache validates a stale response with a conditional HEAD.
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodHead && req.Header.Get(hdrIfNoneMatch) == etagA {
				respond(304, "", hdrCacheControl, "max-age=100", hdrETag, etagA, "X-Head", "1")(writer, req)

				return
			}

			respond(200, bodyText, hdrCacheControl, ccMaxAge1, hdrETag, etagA, hdrContentLength, "4")(writer, req)
		})
		get(t, cache, testURL)
		time.Sleep(2 * time.Second)

		res, body := roundTrip(t, cache, newRequest(http.MethodHead, testURL))
		wantHits(t, srv, 2)

		if res.StatusCode != http.StatusOK || body != "" {
			t.Errorf("HEAD: got %d with body %q, want 200 without one", res.StatusCode, body)
		}

		wantHeader(t, res, "X-Head", "1")
		wantHeader(t, res, hdrContentLength, "4")

		// The 304 refreshed the stored GET response.
		if _, body := get(t, cache, testURL); body != bodyText {
			t.Errorf("GET: body %q", body)
		}

		wantHits(t, srv, 2)
	})
}

func TestNotModifiedWithInvalidDate(t *testing.T) {
	t.Parallel()

	covers(t, "9110-6.6.1-invalid-date")

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, sequence(
			respond(200, "v1", hdrCacheControl, ccMaxAge1, hdrETag, etagV1),
			respond(304, "", hdrCacheControl, "max-age=600", hdrETag, etagV1, hdrDate, "yesterday"),
		))

		get(t, cache, testURL)
		time.Sleep(2 * time.Second)
		get(t, cache, testURL)

		received := formatHTTPDate(time.Now())

		time.Sleep(5 * time.Second)

		res, _ := get(t, cache, testURL)
		wantHeader(t, res, hdrDate, received)
		wantHeader(t, res, hdrAge, "5")
	})
}
