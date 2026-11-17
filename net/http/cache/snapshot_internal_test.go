package cache

import (
	"bytes"
	"crypto/rand"
	"errors"
	"html"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"go.dw1.io/fastcache" //nolint:depguard // depguard has no allowlist without a config
)

const bodySecret = "secret-body"

var errWriteFailed = errors.New("write failed")

// snapshotOf returns a snapshot of cache.
func snapshotOf(tb testing.TB, cache *Transport) []byte {
	tb.Helper()

	var buf bytes.Buffer

	err := cache.Save(&buf)
	if err != nil {
		tb.Fatal(err)
	}

	return buf.Bytes()
}

// loadSnapshot returns a new Transport, in front of an origin that answers
// with handler, that has loaded snapshot.
func loadSnapshot(tb testing.TB, snapshot []byte, handler http.HandlerFunc, opts ...Option) (*Transport, *origin) {
	tb.Helper()

	cache, srv := newTestCache(tb, handler, opts...)

	err := cache.Load(bytes.NewReader(snapshot))
	if err != nil {
		tb.Fatal(err)
	}

	return cache, srv
}

// handMadeSnapshot returns a snapshot that holds responses for testURL.
func handMadeSnapshot(tb testing.TB, responses []snapshotResponse) []byte {
	tb.Helper()

	saved, err := fastcache.New[string, []snapshotResponse](1)
	if err == nil {
		err = saved.Set(testURL, responses)
	}

	buf := bytes.NewBufferString(snapshotMagic)
	if err == nil {
		err = saved.SaveTo(buf)
	}

	if err != nil {
		tb.Fatal(err)
	}

	return buf.Bytes()
}

// revalidatingOrigin answers a request that has If-None-Match: etagA with a 304
// that makes the response fresh for a minute, and any other with a 500.
func revalidatingOrigin(writer http.ResponseWriter, req *http.Request) {
	if req.Header.Get(hdrIfNoneMatch) == etagA {
		respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)

		return
	}

	respond(http.StatusInternalServerError, "")(writer, req)
}

// validated reports whether the last request srv received validated a stored
// response, which is how a test sees that a snapshot's response was loaded.
func validated(srv *origin) bool {
	last := srv.last()

	return last != nil && last.Header.Get(hdrIfNoneMatch) != ""
}

func TestSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			respond(http.StatusOK, html.EscapeString(req.Header.Get(hdrAccept)),
				hdrCacheControl, "max-age=3600", "Vary", hdrAccept, hdrETag, etagA)(writer, req)
		})
		for _, accept := range []string{typePlain, typeHTML} {
			get(t, cache, testURL, hdrAccept, accept)
		}

		snapshot := snapshotOf(t, cache)

		time.Sleep(10 * time.Second)

		restored, srv := loadSnapshot(t, snapshot, revalidatingOrigin)
		for _, accept := range []string{typePlain, typeHTML} {
			// The first use validates the loaded response, and the 304 lets
			// the cache serve its body.
			res, body := get(t, restored, testURL, hdrAccept, accept)
			if res.StatusCode != http.StatusOK || body != accept || !validated(srv) {
				t.Errorf("Accept %s: got %d %q, validated %t", accept, res.StatusCode, body, validated(srv))
			}

			hits := srv.hits()
			if _, body := get(t, restored, testURL, hdrAccept, accept); body != accept || srv.hits() != hits {
				t.Errorf("Accept %s: body %q after validation, %d new origin requests", accept, body, srv.hits()-hits)
			}
		}

		// The Vary fields of the original requests still select the responses.
		get(t, restored, testURL, hdrAccept, "image/png")

		if validated(srv) {
			t.Error("a request with another Accept was answered with a loaded response")
		}
	})
}

func TestSnapshotLoadRevalidates(t *testing.T) {
	covers(t, "9111-4.4-target")
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(http.StatusOK, "v1", hdrCacheControl, "max-age=3600", hdrETag, etagA))
		get(t, cache, testURL)

		// The response changes after the snapshot is saved, for example
		// because of a POST the snapshot doesn't know about. The loaded
		// response is still fresh, but it isn't served unvalidated.
		restored, srv := loadSnapshot(t, snapshotOf(t, cache),
			respond(http.StatusOK, "v2", hdrCacheControl, "max-age=3600", hdrETag, etagB))

		if _, body := get(t, restored, testURL); body != "v2" || !validated(srv) {
			t.Errorf("body %q, validated %t; want v2 after validation", body, validated(srv))
		}
	})
}

func TestSnapshotKeepsServer(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA))

		req := newRequest(http.MethodGet, "http://"+hostBackend+"/r")
		req.Host = hostExample
		roundTrip(t, cache, req)

		restored, srv := loadSnapshot(t, snapshotOf(t, cache), revalidatingOrigin)

		req = newRequest(http.MethodGet, "http://"+hostBackend+"/r")
		req.Host = hostExample

		if _, body := roundTrip(t, restored, req); body != bodyText || !validated(srv) {
			t.Errorf("via the backend: body %q, validated %t", body, validated(srv))
		}

		// The response came from one backend, so it doesn't answer requests
		// sent elsewhere.
		get(t, restored, testURL)

		if validated(srv) {
			t.Error("a request to another server was answered with the loaded response")
		}
	})
}

func TestSnapshotOmits(t *testing.T) {
	covers(t, "9111-5.2.2.5-non-volatile", "9111-5.2.1.5-non-volatile")
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case "/kept":
				respond(http.StatusOK, "kept", hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
			case "/must-understand":
				respond(http.StatusOK, bodySecret, hdrCacheControl, "max-age=60, no-store, must-understand",
					hdrETag, etagA)(writer, req)
			case "/unvalidatable":
				respond(http.StatusOK, bodySecret, hdrCacheControl, ccMaxAge60)(writer, req)
			case "/withdrawn":
				if req.Header.Get(hdrIfNoneMatch) == etagA {
					respond(http.StatusNotModified, "", hdrCacheControl, ccNoStore, hdrETag, etagA)(writer, req)

					return
				}

				respond(http.StatusOK, bodySecret, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
			default:
				respond(http.StatusOK, bodySecret, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
			}
		})

		get(t, cache, "http://example.com/kept")

		// must-understand lets the cache store this response in memory (RFC
		// 9111 §5.2.2.3), but no-store still keeps it off disk.
		get(t, cache, "http://example.com/must-understand")
		get(t, cache, "http://example.com/must-understand")
		wantHits(t, srv, 2)

		// A response to a no-store request isn't stored at all.
		get(t, cache, "http://example.com/no-store-request", hdrCacheControl, ccNoStore)

		// Nor are responses that couldn't be validated after loading, or
		// whose last update couldn't be stored, as this 304 with no-store.
		get(t, cache, "http://example.com/unvalidatable")
		get(t, cache, "http://example.com/withdrawn")
		get(t, cache, "http://example.com/withdrawn", hdrCacheControl, ccNoCache)

		bodies := savedBodies(t, snapshotOf(t, cache))
		if slices.Contains(bodies, bodySecret) {
			t.Error("the snapshot holds a response it must not")
		}

		if !slices.Contains(bodies, "kept") {
			t.Error("the snapshot lacks the response it should hold")
		}
	})
}

// secretOrigin answers a GET with a cacheable response that holds bodySecret,
// a request that validates it or a HEAD with update, and any other method
// with a 204.
func secretOrigin(update http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodHead || req.Header.Get(hdrIfNoneMatch) != "":
			update(writer, req)
		case req.Method == http.MethodGet:
			respond(http.StatusOK, bodySecret, hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
		default:
			respond(http.StatusNoContent, "")(writer, req)
		}
	}
}

// savedBodies returns the bodies of the responses in snapshot. It decodes the
// snapshot, as its compressed data needn't hold a body as it is.
func savedBodies(tb testing.TB, snapshot []byte) []string {
	tb.Helper()

	var bodies []string

	err := fastcache.LoadFromFunc(bytes.NewReader(bytes.TrimPrefix(snapshot, []byte(snapshotMagic))),
		func(_ string, responses []snapshotResponse) error {
			for _, response := range responses {
				bodies = append(bodies, string(response.Body))
			}

			return nil
		})
	if err != nil {
		tb.Fatal(err)
	}

	return bodies
}

// holdsSecret reports whether a snapshot of cache holds bodySecret.
func holdsSecret(tb testing.TB, cache *Transport) bool {
	tb.Helper()

	return slices.Contains(savedBodies(tb, snapshotOf(tb, cache)), bodySecret)
}

func TestSnapshotOmitsWithdrawn(t *testing.T) {
	t.Parallel()

	noStore := respond(http.StatusNotModified, "", hdrCacheControl, ccNoStore, hdrETag, etagA)

	// A withdrawn response stays withdrawn when a POST, or a HEAD that
	// doesn't describe it, marks it invalid again.
	cache, _ := newTestCache(t, secretOrigin(noStore))
	get(t, cache, testURL)
	get(t, cache, testURL, hdrCacheControl, ccNoCache)
	roundTrip(t, cache, newRequest(http.MethodPost, testURL))

	if holdsSecret(t, cache) {
		t.Error("a withdrawn response was written after a POST")
	}

	cache, _ = newTestCache(t, secretOrigin(func(writer http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodHead {
			respond(http.StatusOK, "", hdrCacheControl, ccMaxAge60, hdrETag, etagB)(writer, req)

			return
		}

		noStore(writer, req)
	}))
	get(t, cache, testURL)
	get(t, cache, testURL, hdrCacheControl, ccNoCache)
	roundTrip(t, cache, newRequest(http.MethodHead, testURL))

	if holdsSecret(t, cache) {
		t.Error("a withdrawn response was written after a HEAD that doesn't describe it")
	}

	// A HEAD response that describes the stored response can withdraw it.
	cache, _ = newTestCache(t, secretOrigin(respond(http.StatusOK, "", hdrCacheControl, ccNoStore, hdrETag, etagA)))
	get(t, cache, testURL)
	roundTrip(t, cache, newRequest(http.MethodHead, testURL, hdrCacheControl, ccNoCache))

	if holdsSecret(t, cache) {
		t.Error("a response that a HEAD with no-store describes was written")
	}

	// An update that can be stored makes a withdrawn response writable again.
	cache, _ = newTestCache(t, secretOrigin(sequence(noStore,
		respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA))))
	get(t, cache, testURL)
	get(t, cache, testURL, hdrCacheControl, ccNoCache)
	get(t, cache, testURL, hdrCacheControl, ccNoCache)

	if !holdsSecret(t, cache) {
		t.Error("a response updated after its withdrawal wasn't written")
	}
}

func TestSnapshotOmitsWithdrawnInSharedCache(t *testing.T) {
	t.Parallel()

	// In a shared cache, an update withdraws the response if it adds
	// private, or if it answers a request with Authorization (RFC 9111 §3.5).
	cache, _ := newTestCache(t, secretOrigin(
		respond(http.StatusNotModified, "", hdrCacheControl, "private, max-age=60", hdrETag, etagA)), WithShared())
	get(t, cache, testURL)
	get(t, cache, testURL, hdrCacheControl, ccNoCache)

	if holdsSecret(t, cache) {
		t.Error("a response that a 304 made private was written")
	}

	cache, _ = newTestCache(t, secretOrigin(
		respond(http.StatusNotModified, "", hdrCacheControl, ccMaxAge60, hdrETag, etagA)), WithShared())
	get(t, cache, testURL)
	get(t, cache, testURL, hdrCacheControl, ccNoCache, hdrAuthorization, "Bearer token")

	if holdsSecret(t, cache) {
		t.Error("a response that a 304 to a request with Authorization updated was written")
	}
}

func TestSnapshotOmitsWithdrawnDuringInvalidation(t *testing.T) {
	t.Parallel()

	// A POST while the update is in flight keeps the update from being
	// stored, but not from withdrawing the response, even when a HEAD
	// response has no validator to compare.
	for _, test := range []struct {
		method string
		fields []string
	}{
		{http.MethodGet, []string{hdrCacheControl, ccNoStore, hdrETag, etagA}},
		{http.MethodHead, []string{hdrCacheControl, ccNoStore, hdrETag, etagA}},
		{http.MethodHead, []string{hdrCacheControl, ccNoStore}},
	} {
		var cache *Transport

		cache, _ = newTestCache(t, secretOrigin(func(writer http.ResponseWriter, req *http.Request) {
			roundTrip(t, cache, newRequestContext(req.Context(), http.MethodPost, testURL))

			status := http.StatusNotModified
			if req.Method == http.MethodHead {
				status = http.StatusOK
			}

			respond(status, "", test.fields...)(writer, req)
		}))
		get(t, cache, testURL)
		roundTrip(t, cache, newRequest(test.method, testURL, hdrCacheControl, ccNoCache))

		if holdsSecret(t, cache) {
			t.Errorf("%s with %q: a response whose update said no-store was written", test.method, test.fields)
		}
	}
}

func TestSnapshotLoadAppliesStorageRules(t *testing.T) {
	covers(t, "9111-3-shared-private", "9111-3.5-authorization")
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			body, extra := html.EscapeString(req.URL.Path), html.EscapeString(req.URL.Query().Get("cc"))
			respond(http.StatusOK, body, hdrCacheControl, "max-age=60, "+extra, hdrETag, etagA)(writer, req)
		})

		get(t, cache, "http://example.com/private?cc=private")
		get(t, cache, "http://example.com/auth?cc=x", hdrAuthorization, "Bearer x")
		get(t, cache, "http://example.com/auth-public?cc=public", hdrAuthorization, "Bearer x")
		get(t, cache, "http://example.com/plain?cc=x")
		snapshot := snapshotOf(t, cache)

		// A shared cache loads only what a shared cache may store.
		shared, srv := loadSnapshot(t, snapshot, revalidatingOrigin, WithShared())
		for _, test := range []struct {
			url    string
			loaded bool
		}{
			{"http://example.com/private?cc=private", false},
			{"http://example.com/auth?cc=x", false},
			{"http://example.com/auth-public?cc=public", true},
			{"http://example.com/plain?cc=x", true},
		} {
			get(t, shared, test.url)

			if loaded := validated(srv); loaded != test.loaded {
				t.Errorf("%s: loaded = %t, want %t", test.url, loaded, test.loaded)
			}
		}

		// A private cache with a smaller body limit skips larger bodies.
		small, srv := loadSnapshot(t, snapshot, revalidatingOrigin, WithMaxBodySize(int64(len("/plain"))))
		get(t, small, "http://example.com/plain?cc=x")

		if !validated(srv) {
			t.Error("a body within the limit wasn't loaded")
		}

		get(t, small, "http://example.com/private?cc=private")

		if validated(srv) {
			t.Error("a body over the limit was loaded")
		}
	})
}

// savedResponse returns a fresh, validatable response for a hand-made
// snapshot.
func savedResponse(header http.Header, vary []snapshotVaryField, decoded bool) snapshotResponse {
	return snapshotResponse{
		Status:       http.StatusOK,
		StatusText:   "200 OK",
		Header:       header,
		Body:         []byte(bodyText),
		Decoded:      decoded,
		Authorized:   false,
		RequestTime:  time.Now(),
		ResponseTime: time.Now(),
		Vary:         vary,
		DialHost:     "",
	}
}

func TestSnapshotLoadChecksResponses(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		fresh := func(fields ...string) http.Header {
			header := make(http.Header)
			header.Set(hdrCacheControl, ccMaxAge60)
			header.Set(hdrETag, etagA)

			for name, value := range pairs(fields) {
				header.Set(name, value)
			}

			return header
		}

		cookie := []snapshotVaryField{{Name: "Cookie", Value: "user=a", Present: true}}
		for _, test := range []struct {
			name     string
			response snapshotResponse
			private  bool
			shared   bool
		}{
			{"consistent", savedResponse(fresh("Vary", "Cookie"), cookie, false), true, true},
			// The saved Vary fields must be the ones the header nominates.
			{"Vary without fields", savedResponse(fresh("Vary", "Cookie"), nil, false), false, false},
			{"fields without Vary", savedResponse(fresh(), cookie, false), false, false},
			{"Vary *", savedResponse(fresh("Vary", "*"), nil, false), false, false},
			// A body a private cache decoded is transformed content for a
			// proxy (RFC 9110 §7.7).
			{"decoded", savedResponse(fresh(), nil, true), true, false},
			// Without its header the response has neither freshness nor a
			// validator. Loading it mustn't fail or panic.
			{"no header", savedResponse(nil, nil, false), false, false},
		} {
			snapshot := handMadeSnapshot(t, []snapshotResponse{test.response})

			for _, shared := range []bool{false, true} {
				var opts []Option
				if shared {
					opts = append(opts, WithShared())
				}

				cache, srv := loadSnapshot(t, snapshot, revalidatingOrigin, opts...)
				get(t, cache, testURL, "Cookie", "user=a")

				want := test.private
				if shared {
					want = test.shared
				}

				if loaded := validated(srv); loaded != want {
					t.Errorf("%s, shared %t: loaded = %t, want %t", test.name, shared, loaded, want)
				}
			}
		}
	})
}

func TestSnapshotDetectsDamage(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA))
		get(t, cache, testURL)

		// Change one byte of the body inside the saved stream.
		snapshot := snapshotOf(t, cache)

		pos := bytes.Index(snapshot, []byte(bodyText))
		if pos < 0 {
			t.Fatal("the snapshot doesn't hold the body")
		}

		snapshot[pos] ^= 0x20

		// The origin's 304 can't tell that the body changed, so the damaged
		// response mustn't be loaded at all.
		restored, srv := newTestCache(t, revalidatingOrigin)

		err := restored.Load(bytes.NewReader(snapshot))
		if !errors.Is(err, ErrInvalidSnapshot) {
			t.Errorf("Load error = %v, want ErrInvalidSnapshot", err)
		}

		get(t, restored, testURL)

		if validated(srv) {
			t.Error("a damaged response was loaded")
		}
	})
}

// randomBody returns size random bytes, which minlz can't compress.
func randomBody(size int) string {
	body := make([]byte, size)
	_, _ = rand.Read(body)

	return string(body)
}

func TestSnapshotDetectsSkippedChunk(t *testing.T) {
	t.Parallel()

	// The first body spans several of minlz's 2 MiB chunks. When one of them
	// is skipped, the first response can still decode from the bytes that
	// follow, the zeros of the second body, as gob ends a struct at a zero.
	const urlExampleB = "http://example.com/b"

	bodies := map[string]string{urlExampleA: randomBody(5 << 20), urlExampleB: string(make([]byte, 3<<20))}
	handler := func(writer http.ResponseWriter, req *http.Request) {
		respond(http.StatusOK, bodies[req.URL.String()], hdrCacheControl, ccMaxAge60, hdrETag, etagA)(writer, req)
	}

	cache, _ := newTestCache(t, handler, WithMaxBodySize(8<<20))
	get(t, cache, urlExampleA)
	get(t, cache, urlExampleB)
	snapshot := snapshotOf(t, cache)

	// Each minlz chunk starts with its type and a 3-byte length. Types 0x00
	// to 0x03 hold data, and damage can turn one into a type that minlz skips
	// without a check.
	damagedChunks := 0

	for start := len(snapshotMagic); start+4 <= len(snapshot); {
		length := int(snapshot[start+1]) | int(snapshot[start+2])<<8 | int(snapshot[start+3])<<16

		if snapshot[start] <= 0x03 {
			damaged := bytes.Clone(snapshot)
			damaged[start] |= 0x80

			restored, _ := newTestCache(t, handler, WithMaxBodySize(8<<20))

			err := restored.Load(bytes.NewReader(damaged))
			if !errors.Is(err, ErrInvalidSnapshot) {
				t.Errorf("chunk at %d: Load error = %v, want ErrInvalidSnapshot", start, err)
			}

			for key, stored := range restored.entries.All() {
				for _, response := range stored.variants {
					if string(response.body) != bodies[key] {
						t.Errorf("chunk at %d: %s was loaded with a damaged body", start, key)
					}
				}
			}

			damagedChunks++
		}

		start += 4 + length
	}

	if damagedChunks < 3 {
		t.Errorf("damaged %d data chunks, want at least 3", damagedChunks)
	}
}

func TestSnapshotLoadSkipsTooLarge(t *testing.T) {
	t.Parallel()

	cache, srv := newTestCache(t, sizedByAccept, WithMaxBytes(1000), WithMaxVariants(1))
	get(t, cache, testURL, hdrAccept, "small")

	// The saved response is newer, but too large for this cache, so loading
	// it leaves the one stored for Accept small alone.
	saved, _ := newTestCache(t, sizedByAccept)
	get(t, saved, testURL, hdrAccept, "big")

	err := cache.Load(bytes.NewReader(snapshotOf(t, saved)))
	if err != nil {
		t.Fatal(err)
	}

	get(t, cache, testURL, hdrAccept, "small")
	wantHits(t, srv, 1)
}

func TestSnapshotLoadKeepsStoredResponses(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, srv := newTestCache(t, sequence(
			respond(http.StatusOK, "v1", hdrCacheControl, ccMaxAge60, hdrETag, etagA),
			respond(http.StatusNoContent, ""),
			respond(http.StatusOK, "v2", hdrCacheControl, ccMaxAge60, hdrETag, etagB),
		))

		get(t, cache, testURL)
		snapshot := snapshotOf(t, cache)

		// After a POST invalidates v1, loading the older snapshot leaves the
		// stored response invalid.
		roundTrip(t, cache, newRequest(http.MethodPost, testURL))

		err := cache.Load(bytes.NewReader(snapshot))
		if err != nil {
			t.Fatal(err)
		}

		if _, body := get(t, cache, testURL); body != "v2" {
			t.Errorf("body = %q, want v2 from the origin", body)
		}

		wantHits(t, srv, 3)

		// Nor does it replace the newer v2.
		err = cache.Load(bytes.NewReader(snapshot))
		if err != nil {
			t.Fatal(err)
		}

		if _, body := get(t, cache, testURL); body != "v2" {
			t.Errorf("body = %q, want the stored v2", body)
		}

		wantHits(t, srv, 3)
	})
}

func TestSnapshotKeepsEvictionOrder(t *testing.T) {
	t.Parallel()

	const stored, kept = 20, 5

	handler := respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA)

	cache, _ := newTestCache(t, handler)
	for n := range stored {
		get(t, cache, testURL+strconv.Itoa(n))
	}

	// A new response for the first URI leaves it first to be evicted, as
	// fastcache keeps an updated key's place.
	get(t, cache, testURL+"0", hdrCacheControl, ccNoCache)

	newest := func(count int) []string {
		var urls []string
		for n := stored - count; n < stored; n++ {
			urls = append(urls, testURL+strconv.Itoa(n))
		}

		return urls
	}

	// A URI stored before Load is evicted before the loaded ones.
	restored, _ := newTestCache(t, handler, WithMaxEntries(kept))
	get(t, restored, testURL+"-before")

	err := restored.Load(bytes.NewReader(snapshotOf(t, cache)))
	if err != nil {
		t.Fatal(err)
	}

	if got := slices.Sorted(restored.entries.Keys()); !slices.Equal(got, newest(kept)) {
		t.Errorf("loaded %q, want the newest %q", got, newest(kept))
	}

	// Using the loaded responses in another order doesn't change their order.
	for _, url := range slices.Backward(newest(kept)) {
		get(t, restored, url)
	}

	again, _ := loadSnapshot(t, snapshotOf(t, restored), handler, WithMaxEntries(2))
	if got := slices.Sorted(again.entries.Keys()); !slices.Equal(got, newest(2)) {
		t.Errorf("loaded again %q, want the newest %q", got, newest(2))
	}
}

func TestSnapshotWritesResponsesToValidate(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const invalidated = testURL + "-invalidated"

		cache, _ := newTestCache(t, respond(http.StatusOK, "v1", hdrCacheControl, "max-age=3600", hdrETag, etagA))
		get(t, cache, testURL)
		get(t, cache, invalidated)
		roundTrip(t, cache, newRequest(http.MethodPost, invalidated))

		// Save writes a response that an unsafe request invalidated, and
		// loaded responses that no request has used, because Load requires
		// every response it adds to be validated before use anyway.
		loaded, _ := loadSnapshot(t, snapshotOf(t, cache), revalidatingOrigin)
		restored, srv := loadSnapshot(t, snapshotOf(t, loaded), revalidatingOrigin)

		for _, url := range []string{testURL, invalidated} {
			hits := srv.hits()

			res, body := get(t, restored, url)
			if res.StatusCode != http.StatusOK || body != "v1" || srv.hits() != hits+1 || !validated(srv) {
				t.Errorf("%s: got %d %q after %d origin requests, validated %t",
					url, res.StatusCode, body, srv.hits()-hits, validated(srv))
			}
		}
	})
}

func TestSnapshotLoadKeepsVariantLimits(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(http.StatusOK, strings.Repeat("x", 600),
			hdrCacheControl, ccMaxAge60, hdrETag, etagA, "Vary", hdrAccept))
		for _, accept := range []string{"a", "b", "c"} {
			get(t, cache, testURL, hdrAccept, accept)
			time.Sleep(time.Second)
		}

		// A Transport with a lower limit keeps the newest responses. One
		// 600-byte response fits in 1000 bytes, and two don't.
		for _, test := range []struct {
			limit Option
			want  []string
		}{{WithMaxVariants(2), []string{"b", "c"}}, {WithMaxBytes(1000), []string{"c"}}} {
			restored, _ := loadSnapshot(t, snapshotOf(t, cache), revalidatingOrigin, test.limit)

			var kept []string

			for _, stored := range restored.entries.All() {
				for _, response := range stored.variants {
					kept = append(kept, response.vary[0].value)
				}
			}

			slices.Sort(kept)

			if !slices.Equal(kept, test.want) {
				t.Errorf("Load kept the responses for Accept %q, want %q", kept, test.want)
			}
		}
	})
}

func TestSnapshotInvalid(t *testing.T) {
	t.Parallel()

	cache, _ := newTestCache(t, respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA))
	get(t, cache, testURL)
	valid := snapshotOf(t, cache)

	tests := []struct {
		name string
		data []byte
	}{
		{"not a snapshot", []byte(bodyHello)},
		{"other format", bytes.Replace(valid, []byte("cache snapshot"), []byte("cache archives"), 1)},
		{"other version", bytes.Replace(valid, []byte("snapshot v1"), []byte("snapshot v2"), 1)},
		{"no data", []byte(snapshotMagic)},
		{"not fastcache data", []byte(snapshotMagic + bodyHello)},
	}

	// A truncated snapshot doesn't load without an error, even when only the
	// end of the compressed stream is missing.
	for size := range valid {
		empty, _ := newTestCache(t, respond(http.StatusOK, ""))

		err := empty.Load(bytes.NewReader(valid[:size]))
		if !errors.Is(err, ErrInvalidSnapshot) {
			t.Errorf("first %d bytes: Load error = %v, want ErrInvalidSnapshot", size, err)
		}
	}

	for _, test := range tests {
		empty, _ := newTestCache(t, respond(http.StatusOK, ""))

		err := empty.Load(bytes.NewReader(test.data))
		if !errors.Is(err, ErrInvalidSnapshot) || empty.entries.Len() != 0 {
			t.Errorf("%s: Load error = %v after loading %d target URIs, want ErrInvalidSnapshot and none",
				test.name, err, empty.entries.Len())
		}
	}

	err := cache.Save(&failingWriter{room: 0})
	if !errors.Is(err, errWriteFailed) {
		t.Errorf("Save to a failing writer: error = %v", err)
	}
}

// failingWriter accepts room bytes, then fails every write.
type failingWriter struct {
	room int
}

func (w *failingWriter) Write(data []byte) (int, error) {
	written := min(len(data), w.room)
	w.room -= written

	if written < len(data) {
		return written, errWriteFailed
	}

	return written, nil
}

func TestSnapshotIOErrors(t *testing.T) {
	t.Parallel()

	// synctest.Test fails if a goroutine that Save or Load started is still
	// blocked when it returns.
	synctest.Test(t, func(t *testing.T) {
		// More than one of minlz's 2 MiB blocks, so a write fails while the
		// rest of the snapshot is still being encoded.
		cache, _ := newTestCache(t, respond(http.StatusOK, randomBody(3<<20), hdrCacheControl, ccMaxAge60, hdrETag, etagA),
			WithMaxBodySize(4<<20))
		for n := range 4 {
			get(t, cache, testURL+strconv.Itoa(n))
		}

		valid := snapshotOf(t, cache)

		// The last two sizes end within the final data chunk and within the
		// chunk that ends the compressed stream.
		sizes := []int{0, len(snapshotMagic), len(snapshotMagic) + 10, len(valid) / 2, len(valid) - 16, len(valid) - 1}
		for _, size := range sizes {
			err := cache.Save(&failingWriter{room: size})
			if !errors.Is(err, errWriteFailed) {
				t.Errorf("Save failing after %d bytes: error = %v, want errWriteFailed", size, err)
			}

			empty, _ := newTestCache(t, respond(http.StatusOK, ""))

			err = empty.Load(io.MultiReader(bytes.NewReader(valid[:size]), iotest.ErrReader(errReadFailed)))
			if !errors.Is(err, errReadFailed) || !errors.Is(err, ErrInvalidSnapshot) {
				t.Errorf("Load failing after %d bytes: error = %v, want ErrInvalidSnapshot and errReadFailed", size, err)
			}
		}
	})
}

func TestSnapshotThroughPipe(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		cache, _ := newTestCache(t, respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA))
		get(t, cache, testURL)

		reader, writer := io.Pipe()
		saved := make(chan error, 1)

		// Closing the reader ends a Save that is still writing, so a failed
		// test doesn't leave it blocked.
		defer func() { _ = reader.Close() }()

		go func() { saved <- cache.Save(writer) }()

		restored, srv := newTestCache(t, revalidatingOrigin)

		err := restored.Load(reader)
		if err != nil {
			t.Fatal(err)
		}

		// Load reads the whole snapshot, so Save returns without the pipe
		// being closed.
		synctest.Wait()

		select {
		case err := <-saved:
			if err != nil {
				t.Errorf("Save error = %v", err)
			}
		default:
			t.Error("Save is still writing after Load returned")

			_ = reader.Close()

			t.Logf("Save error after closing the pipe: %v", <-saved)
		}

		if get(t, restored, testURL); !validated(srv) {
			t.Error("the response wasn't loaded")
		}
	})
}

func TestSnapshotConcurrentUse(t *testing.T) {
	// Run with -race. Save and Load share entries with requests.
	t.Parallel()

	cache, _ := newTestCache(t, respond(http.StatusOK, bodyText, hdrCacheControl, ccMaxAge60, hdrETag, etagA))
	get(t, cache, testURL)
	snapshot := snapshotOf(t, cache)

	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			for range 50 {
				get(t, cache, testURL)
				roundTrip(t, cache, newRequest(http.MethodPost, urlExampleA))

				err := cache.Save(io.Discard)
				if err != nil {
					t.Error(err)
				}

				err = cache.Load(bytes.NewReader(snapshot))
				if err != nil {
					t.Error(err)
				}
			}
		})
	}

	group.Wait()
}
