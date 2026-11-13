package cache

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

func TestFreshResponseIsReused(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-freshness", "9111-4-age", "9111-4.2.3-age", "9111-3-max-age", "9110-9.3.1-get-reuse")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, bodyHello, hdrCacheControl, ccMaxAge60, hdrAge, "5"))

		get(t, cache, testURL)
		time.Sleep(10 * time.Second)

		res, body := get(t, cache, testURL)
		wantHits(t, srv, 1)

		if body != bodyHello {
			t.Errorf("body = %q, want hello", body)
		}

		// The stored Age is replaced by the current age.
		wantHeader(t, res, hdrAge, "15")

		if n := len(res.Header.Values(hdrAge)); n != 1 {
			t.Errorf("got %d Age fields", n)
		}

		// At age 60 the response is stale.
		time.Sleep(45 * time.Second)
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestAgeCalculation(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.2.3-age", "9111-4.2.3-request-time")

	synctest.Test(t, func(t *testing.T) {
		// An origin whose clock is 30 seconds slow: apparent_age is 30.
		cache, _ := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60,
			hdrDate, formatHTTPDate(time.Now().Add(-30*time.Second))))
		get(t, cache, testURL)
		res, _ := get(t, cache, testURL)
		wantHeader(t, res, hdrAge, "30")
	})

	synctest.Test(t, func(t *testing.T) {
		// A response that takes 3 seconds and reports Age 10 is 13 seconds
		// old on arrival: Age counts from when the request was sent.
		cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			writer.Header().Set(hdrDate, formatHTTPDate(time.Now()))
			time.Sleep(3 * time.Second)
			respond(200, "", hdrCacheControl, ccMaxAge60, hdrAge, "10")(writer, req)
		})
		get(t, cache, testURL)
		res, _ := get(t, cache, testURL)
		wantHeader(t, res, hdrAge, "13")
	})
}

func TestAgeOverflow(t *testing.T) {
	t.Parallel()

	covers(t, "9111-1.2.2-overflow")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, "max-age=3600", hdrAge, "2147483649"))
		get(t, cache, testURL)
		get(t, cache, testURL)
		wantHits(t, srv, 2)

		res, _ := get(t, cache, testURL, hdrCacheControl, ccMaxStale)
		wantHits(t, srv, 2)
		wantHeader(t, res, hdrAge, "2147483648")
	})
}

func TestNoStoreResponse(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3-no-store", "9111-5.2.2.5-no-store", "9111-5.2.2.5-no-reuse", "9111-5.2.2-obey")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(200, "a", hdrCacheControl, ccMaxAge60),
			respond(200, "b", hdrCacheControl, "nO-StOrE, max-age=60"),
			respond(200, "c", hdrCacheControl, "no-store, max-age=60"),
		))

		get(t, cache, testURL)
		// The no-store response doesn't replace the stored one.
		get(t, cache, testURL, hdrCacheControl, ccNoCache)

		if _, body := get(t, cache, testURL); body != "a" {
			t.Errorf("body = %q, want the stored a", body)
		}

		wantHits(t, srv, 2)

		cache, srv = newTestCache(t, respond(200, "", hdrCacheControl, "no-store, max-age=60",
			hdrExpires, formatHTTPDate(time.Now().Add(time.Hour))))
		get(t, cache, testURL)
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestNoCacheResponse(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-no-cache", "9111-5.2.2.4-no-cache", "9111-5.2.2-obey")

	for _, control := range []string{"no-cache, max-age=60", "No-CaChE, max-age=60", `no-cache="Set-Cookie", max-age=60`} {
		t.Run(control, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, control, hdrETag, etagA))
				get(t, cache, testURL)
				get(t, cache, testURL)
				wantHits(t, srv, 2)

				if got := srv.last().Header.Get(hdrIfNoneMatch); got != etagA {
					t.Errorf("%s: If-None-Match = %q, want a validation request", control, got)
				}

				// Request max-stale doesn't allow it either.
				get(t, cache, testURL, hdrCacheControl, ccMaxStale)
				wantHits(t, srv, 3)
			})
		})
	}
}

func TestStaleResponse(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-4.2.4-prohibited",
		"9111-4.2.4-permitted",
		"9111-5.2.2.2-stale-reuse",
		"9111-5.2.2.2-no-ignore",
		"9111-5.2.2.8-stale-reuse",
		"9111-5.2.2.10-stale-reuse",
		"9111-5.2.1-optional",
		"9111-5.2.2-obey",
	)

	for _, test := range []struct {
		cc       string
		shared   bool
		reusable bool
	}{
		{ccMaxAge1, false, true},
		{ccMaxAge1, true, true},
		{ccMaxAge1Revalidate, false, false},
		{ccMaxAge1Revalidate, true, false},
		{"max-age=1, proxy-revalidate", false, true},
		{"max-age=1, proxy-revalidate", true, false},
		{"s-maxage=1", true, false},
		{"max-age=1, s-maxage=1", false, true},
	} {
		// After 5 seconds the response is 4 seconds stale. Only the request
		// can allow serving it, and only within its max-stale.
		for _, req := range []struct {
			cc  string
			hit bool
		}{
			{"", false},
			{ccMaxStale, test.reusable},
			{"max-stale=4", test.reusable},
			{"max-stale=10", test.reusable},
			{"max-stale=3", false},
		} {
			t.Run(fmt.Sprintf("%s/shared=%t/%s", test.cc, test.shared, req.cc), func(t *testing.T) {
				t.Parallel()

				synctest.Test(t, func(t *testing.T) {
					var opts []Option
					if test.shared {
						opts = append(opts, WithShared())
					}

					cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, test.cc), opts...)
					get(t, cache, testURL)
					time.Sleep(5 * time.Second)
					get(t, cache, testURL, hdrCacheControl, req.cc)

					if hit := srv.hits() == 1; hit != req.hit {
						t.Errorf("%q, shared %t, request %q: hit = %t, want %t", test.cc, test.shared, req.cc, hit, req.hit)
					}
				})
			})
		}
	}
}

func TestDisconnected(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.2.2-disconnected", "9111-4.2.4-permitted")

	for _, control := range []string{ccMaxAge1, ccMaxAge1Revalidate} {
		t.Run(control, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, control, hdrETag, etagA))
				get(t, cache, testURL)
				time.Sleep(5 * time.Second)

				srv.fail(errOffline)

				res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
				if res != nil {
					_ = res.Body.Close()
				}

				if !errors.Is(err, errOffline) || res != nil {
					t.Errorf("%s: RoundTrip = %v, %v; want the transport error", control, res, err)
				}
			})
		})
	}
}

func TestRequestDirectives(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.1-optional")

	for _, test := range []struct {
		cc     string
		hit    bool
		reason string
	}{
		{"", true, "fresh"},
		{"max-age=20", true, "age 10 <= 20"},
		{"max-age=10", true, "age 10 <= 10"},
		{"max-age=9", false, "age 10 > 9"},
		{ccMaxAge0, false, "age 10 > 0"},
		{"min-fresh=50", true, "50s of freshness left"},
		{"min-fresh=51", false, "only 50s of freshness left"},
		{ccNoCache, false, "validation required"},
		{ccNoStore, true, "no-store doesn't prevent reuse"},
		{"NO-CACHE", false, "case-insensitive"},
		{"max-stale=0", true, "still fresh"},
	} {
		t.Run(test.cc, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60))
				get(t, cache, testURL)
				time.Sleep(10 * time.Second)
				get(t, cache, testURL, hdrCacheControl, test.cc)

				if hit := srv.hits() == 1; hit != test.hit {
					t.Errorf("Cache-Control: %s: hit = %t, want %t (%s)", test.cc, hit, test.hit, test.reason)
				}
			})
		})
	}
}

func TestOnlyIfCached(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.1.7-only-if-cached", "9111-5.2.1-optional")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, bodyHello, hdrCacheControl, ccMaxAge60))

		res, _ := get(t, cache, testURL, hdrCacheControl, "only-if-cached")
		wantHits(t, srv, 0)

		if res.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("empty cache: status %d, want 504", res.StatusCode)
		}

		wantHeader(t, res, hdrDate, formatHTTPDate(time.Now()))

		get(t, cache, testURL)

		res, body := get(t, cache, testURL, hdrCacheControl, "only-if-cached")
		if res.StatusCode != http.StatusOK || body != bodyHello {
			t.Errorf("stored: got %d %q, want the stored response", res.StatusCode, body)
		}

		time.Sleep(time.Minute)

		res, _ = get(t, cache, testURL, hdrCacheControl, "only-if-cached")
		if res.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("stale: status %d, want 504", res.StatusCode)
		}

		res, _ = get(t, cache, testURL, hdrCacheControl, "only-if-cached, max-stale")
		if res.StatusCode != http.StatusOK {
			t.Errorf("stale with max-stale: status %d, want 200", res.StatusCode)
		}

		wantHits(t, srv, 1)
	})
}

func TestOnlyIfCachedBypassed(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.1.7-only-if-cached")

	// A request that can't use the stored response gets a 504 rather than
	// going to the origin.
	cache, srv := newTestCache(t, respond(http.StatusOK, bodyHello, hdrCacheControl, ccMaxAge60))
	get(t, cache, testURL)

	for _, req := range []*http.Request{
		newRequest(http.MethodGet, testURL, hdrCacheControl, "only-if-cached", "Range", "bytes=0-1"),
		newRequest(http.MethodGet, "ftp://example.com/r", hdrCacheControl, "only-if-cached"),
	} {
		if res, _ := roundTrip(t, cache, req); res.StatusCode != http.StatusGatewayTimeout {
			t.Errorf("%s with %q: status %d, want 504", req.URL, req.Header, res.StatusCode)
		}
	}

	wantHits(t, srv, 1)
}

func TestRequestNoStore(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.1.5-no-store", "9111-5.2.1-optional")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(200, "a", hdrCacheControl, ccMaxAge60, hdrETag, etagA),
			respond(200, "b", hdrCacheControl, ccMaxAge1, hdrETag, etagB),
			respond(304, "", hdrCacheControl, ccMaxAge60, hdrETag, etagB),
			respond(200, "c", hdrCacheControl, ccMaxAge60, hdrETag, `"c"`),
		))

		// A full response to a no-store request isn't stored.
		get(t, cache, testURL, hdrCacheControl, ccNoStore)
		get(t, cache, testURL)
		wantHits(t, srv, 2)

		// A 304 to a no-store request doesn't update the stored response.
		time.Sleep(2 * time.Second)

		res, _ := get(t, cache, testURL, hdrCacheControl, ccNoStore, hdrIfNoneMatch, etagB)
		if res.StatusCode != http.StatusNotModified {
			t.Errorf("status %d, want the origin's 304", res.StatusCode)
		}

		// The cache adds no validators to a no-store request, and doesn't
		// store the full response.
		get(t, cache, testURL, hdrCacheControl, ccNoStore)

		if got := srv.last().Header.Get(hdrIfNoneMatch); got != "" {
			t.Errorf("no-store request got If-None-Match %q", got)
		}

		// So b is still stored, and still stale.
		get(t, cache, testURL)
		wantHits(t, srv, 5)

		if got := srv.last().Header.Get(hdrIfNoneMatch); got != etagB {
			t.Errorf("If-None-Match = %q, want b's ETag", got)
		}
	})
}

func TestHeuristicFreshness(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.2.2-heuristic", "9111-3-heuristic-status")

	synctest.Test(t, func(t *testing.T) {
		lm := formatHTTPDate(time.Now().Add(-10 * 24 * time.Hour))
		cache, srv := newTestCache(t, respond(200, "", hdrLastModified, lm))
		get(t, cache, testURL)
		time.Sleep(23 * time.Hour)
		get(t, cache, testURL)
		wantHits(t, srv, 1)

		time.Sleep(2 * time.Hour)
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})

	synctest.Test(t, func(t *testing.T) {
		lm := formatHTTPDate(time.Now().Add(-10 * 24 * time.Hour))
		cache, srv := newTestCache(t, respond(201, "", hdrLastModified, lm))
		get(t, cache, testURL)
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}

func TestExpires(t *testing.T) {
	t.Parallel()

	covers(t, "9111-3-expires", "9111-5.3-invalid-date", "9111-5.3-ignore-max-age", "9111-5.3-ignore-s-maxage")

	// fromNow returns an HTTP-date d from now, inside the synctest bubble.
	fromNow := func(d time.Duration) string { return formatHTTPDate(time.Now().Add(d)) }

	for _, test := range []struct {
		fields func() []string
		shared bool
		hit    bool
	}{
		{func() []string { return []string{hdrExpires, fromNow(time.Minute)} }, false, true},
		{func() []string { return []string{hdrExpires, fromNow(0)} }, false, false},
		{func() []string { return []string{hdrExpires, "0"} }, false, false},
		{func() []string { return []string{hdrExpires, "Thu, 18 Aug 2050 02:01:18 UTC"} }, false, false},
		{func() []string { return []string{hdrExpires, fromNow(time.Minute), hdrCacheControl, ccMaxAge0} }, false, false},
		{func() []string { return []string{hdrExpires, fromNow(-time.Minute), hdrCacheControl, ccMaxAge60} }, false, true},
		{func() []string { return []string{hdrExpires, fromNow(time.Minute), hdrCacheControl, "s-maxage=0"} }, true, false},
		{func() []string { return []string{hdrExpires, fromNow(time.Minute), hdrCacheControl, "s-maxage=0"} }, false, true},
	} {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var opts []Option
				if test.shared {
					opts = append(opts, WithShared())
				}

				fields := test.fields()
				cache, srv := newTestCache(t, respond(200, "", fields...), opts...)
				get(t, cache, testURL)
				time.Sleep(time.Second)
				get(t, cache, testURL)

				if hit := srv.hits() == 1; hit != test.hit {
					t.Errorf("%q, shared %t: hit = %t, want %t", fields, test.shared, hit, test.hit)
				}
			})
		})
	}
}

func TestSharedCache(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-3.5-authorization",
		"9111-3-shared-auth",
		"9111-3-shared-private",
		"9111-5.2.2.7-shared",
		"9111-5.2.2-obey",
	)

	for _, test := range []struct {
		cc         string
		auth       bool
		privateHit bool
		sharedHit  bool
	}{
		{ccMaxAge60, true, true, false},
		{"max-age=60, public", true, true, true},
		{"max-age=60, must-revalidate", true, true, true},
		// A private cache ignores s-maxage, so nothing makes it fresh.
		{ccSMaxAge60, true, false, true},
		{"max-age=60, private", false, true, false},
		{`max-age=60, private="X-User"`, false, true, false},
		{ccMaxAge60, false, true, true},
	} {
		t.Run(test.cc, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				var fields []string
				if test.auth {
					fields = []string{hdrAuthorization, "Bearer x"}
				}

				for _, shared := range []bool{false, true} {
					var opts []Option
					if shared {
						opts = append(opts, WithShared())
					}

					cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, test.cc), opts...)
					get(t, cache, testURL, fields...)
					get(t, cache, testURL)

					hit := srv.hits() == 1

					want := test.privateHit
					if shared {
						want = test.sharedHit
					}

					if hit != want {
						t.Errorf("%q, Authorization %t, shared %t: hit = %t, want %t", test.cc, test.auth, shared, hit, want)
					}
				}
			})
		})
	}
}

func TestVary(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-vary", "9111-4.1-vary-match")

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			lang := html.EscapeString(req.Header.Get("Accept-Language"))
			respond(200, lang, hdrCacheControl, ccMaxAge60, "Vary", "Accept-Language")(writer, req)
		})

		get(t, cache, testURL, "Accept-Language", "en")
		get(t, cache, testURL, "Accept-Language", "fr")
		get(t, cache, testURL)
		wantHits(t, srv, 3)

		for _, lang := range []string{"en", "fr", ""} {
			var fields []string
			if lang != "" {
				fields = []string{"Accept-Language", lang}
			}

			if _, body := get(t, cache, testURL, fields...); body != lang {
				t.Errorf("Accept-Language %q: body = %q", lang, body)
			}
		}

		wantHits(t, srv, 3)
	})

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, respond(200, "", hdrCacheControl, ccMaxAge60, "Vary", "*"))
		get(t, cache, testURL)
		get(t, cache, testURL)
		wantHits(t, srv, 2)
	})
}
