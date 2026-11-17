package cache

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStats(t *testing.T) {
	t.Parallel()

	cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set(hdrCacheControl, ccMaxAge60)
		writer.Header().Set(hdrETag, etagA)

		if req.Header.Get(hdrIfNoneMatch) == etagA {
			writer.WriteHeader(http.StatusNotModified)

			return
		}

		_, _ = io.WriteString(writer, bodyHello)
	})

	var want Stats

	// Each GET or HEAD request adds to exactly one of Hits, Revalidations,
	// Misses, and Bypasses.
	for _, step := range []struct {
		name   string
		req    *http.Request
		counts []*uint64
	}{
		{"first GET", newRequest(http.MethodGet, testURL), []*uint64{&want.Misses, &want.Stores}},
		{"fresh GET", newRequest(http.MethodGet, testURL), []*uint64{&want.Hits}},
		{"fresh HEAD", newRequest(http.MethodHead, testURL), []*uint64{&want.Hits}},
		{"client's own If-None-Match", newRequest(http.MethodGet, testURL, hdrIfNoneMatch, etagA), []*uint64{&want.Hits}},
		{"no-cache", newRequest(http.MethodGet, testURL, hdrCacheControl, ccNoCache), []*uint64{&want.Revalidations}},
		{"no-store", newRequest(http.MethodGet, urlExampleA, hdrCacheControl, ccNoStore), []*uint64{&want.Misses}},
		{
			"only-if-cached without a stored response",
			newRequest(http.MethodGet, urlExampleA, hdrCacheControl, "only-if-cached"),
			[]*uint64{&want.Misses},
		},
		{"Upgrade", newRequest(http.MethodGet, testURL, hdrUpgrade, "websocket"), []*uint64{&want.Bypasses}},
		{
			"Upgrade with only-if-cached",
			newRequest(http.MethodGet, testURL, hdrUpgrade, "websocket", hdrCacheControl, "only-if-cached"),
			[]*uint64{&want.Bypasses},
		},
		{"other scheme", newRequest(http.MethodGet, "ftp://example.com/r"), []*uint64{&want.Bypasses}},
		{"OPTIONS", newRequest(http.MethodOptions, testURL), nil},
		{"POST", newRequest(http.MethodPost, testURL), nil},
		// The POST invalidated the stored response, and the origin's 304
		// makes it usable again.
		{"GET after POST", newRequest(http.MethodGet, testURL), []*uint64{&want.Revalidations}},
	} {
		roundTrip(t, cache, step.req)

		for _, count := range step.counts {
			*count++
		}

		if got := cache.Stats(); got != want {
			t.Fatalf("after %s: Stats() = %+v, want %+v", step.name, got, want)
		}
	}
}

func TestStatsError(t *testing.T) {
	t.Parallel()

	// A request that the next RoundTripper fails is a miss.
	cache, srv := newTestCache(t, respond(http.StatusOK, bodyHello, hdrCacheControl, ccMaxAge60))
	srv.fail(errOffline)

	res, err := cache.RoundTrip(newRequest(http.MethodGet, testURL))
	if res != nil {
		_ = res.Body.Close()
	}

	if !errors.Is(err, errOffline) || res != nil {
		t.Fatalf("RoundTrip = %v, %v; want the transport error", res, err)
	}

	want := Stats{Hits: 0, Revalidations: 0, Misses: 1, Bypasses: 0, Stores: 0, Evictions: 0, Drops: 0}
	if got := cache.Stats(); got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
}

func TestStatsLimits(t *testing.T) {
	t.Parallel()

	varying := respond(http.StatusOK, strings.Repeat("x", 600), hdrCacheControl, ccMaxAge60, "Vary", hdrAccept)

	for _, test := range []struct {
		name   string
		opt    Option
		fields [][]string // the URL and header fields of each GET request
		want   Stats
	}{
		{
			// The second target URI evicts the first.
			"max entries", WithMaxEntries(1),
			[][]string{{urlExampleA}, {testURL}},
			Stats{Hits: 0, Revalidations: 0, Misses: 2, Bypasses: 0, Stores: 2, Evictions: 1, Drops: 0},
		},
		{
			// The second response for a target URI drops the first.
			"max variants", WithMaxVariants(1),
			[][]string{{testURL, hdrAccept, "a"}, {testURL, hdrAccept, "b"}},
			Stats{Hits: 0, Revalidations: 0, Misses: 2, Bypasses: 0, Stores: 2, Evictions: 0, Drops: 1},
		},
		{
			// One response fits and two don't, so the target URI keeps only
			// the newest.
			"max bytes for one target URI", WithMaxBytes(1000),
			[][]string{{testURL, hdrAccept, "a"}, {testURL, hdrAccept, "b"}},
			Stats{Hits: 0, Revalidations: 0, Misses: 2, Bypasses: 0, Stores: 2, Evictions: 0, Drops: 1},
		},
		{
			// One target URI fits, so the second evicts the first.
			"max bytes for two target URIs", WithMaxBytes(1000),
			[][]string{{urlExampleA, hdrAccept, "a"}, {testURL, hdrAccept, "a"}},
			Stats{Hits: 0, Revalidations: 0, Misses: 2, Bypasses: 0, Stores: 2, Evictions: 1, Drops: 0},
		},
		{
			// With its header, the response is too large to store at all.
			"max bytes for one response", WithMaxBytes(600),
			[][]string{{testURL, hdrAccept, "a"}, {testURL, hdrAccept, "a"}},
			Stats{Hits: 0, Revalidations: 0, Misses: 2, Bypasses: 0, Stores: 0, Evictions: 0, Drops: 0},
		},
	} {
		cache, _ := newTestCache(t, varying, test.opt)
		for _, fields := range test.fields {
			get(t, cache, fields[0], fields[1:]...)
		}

		if got := cache.Stats(); got != test.want {
			t.Errorf("%s: Stats() = %+v, want %+v", test.name, got, test.want)
		}
	}
}

func TestStatsLoad(t *testing.T) {
	t.Parallel()

	handler := respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA)

	saved, _ := newTestCache(t, handler)
	get(t, saved, testURL)
	get(t, saved, urlExampleA)

	var snapshot bytes.Buffer

	err := saved.Save(&snapshot)
	if err != nil {
		t.Fatal(err)
	}

	cache, _ := newTestCache(t, handler)

	err = cache.Load(&snapshot)
	if err != nil {
		t.Fatal(err)
	}

	// Loaded responses count as stored, and loading made no requests.
	want := Stats{Hits: 0, Revalidations: 0, Misses: 0, Bypasses: 0, Stores: 2, Evictions: 0, Drops: 0}
	if got := cache.Stats(); got != want {
		t.Errorf("after Load: Stats() = %+v, want %+v", got, want)
	}
}
