package cache

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestWithNext(t *testing.T) {
	t.Parallel()

	handler := respond(http.StatusOK, bodyHello, hdrCacheControl, ccMaxAge60)
	viaA, srvA := newTestCache(t, handler)
	srvB := &origin{handler: handler, mu: sync.Mutex{}, reqs: nil, err: nil}
	viaB := viaA.WithNext(srvB)

	// A response stored through one Transport answers requests through the
	// other.
	get(t, viaA, testURL)
	get(t, viaB, testURL)
	wantHits(t, srvA, 1)
	wantHits(t, srvB, 0)

	// A request the cache can't answer goes to the next RoundTripper of the
	// Transport it was sent through.
	get(t, viaB, urlExampleA)
	get(t, viaA, urlExampleA)
	wantHits(t, srvA, 1)
	wantHits(t, srvB, 1)

	// An unsafe request through either invalidates the response for both.
	roundTrip(t, viaB, newRequest(http.MethodPost, testURL))
	get(t, viaA, testURL)
	wantHits(t, srvA, 2)

	want := Stats{Hits: 2, Revalidations: 0, Misses: 3, Bypasses: 0, Stores: 3, Evictions: 0, Drops: 0}
	for _, cache := range []*Transport{viaA, viaB} {
		if got := cache.Stats(); got != want {
			t.Errorf("Stats() = %+v, want %+v", got, want)
		}
	}

	if next := viaA.WithNext(nil).next; next != http.DefaultTransport {
		t.Errorf("WithNext(nil) sends requests to %T, want http.DefaultTransport", next)
	}
}

func TestWithNextInFlightResponseNotStored(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.4-target")

	// The response to a GET through one Transport arrives after a POST to the
	// same URI through another.
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})

		var gets atomic.Int32

		viaA, srv := newTestCache(t, func(writer http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodGet && gets.Add(1) == 1 {
				<-release
			}

			respond(http.StatusOK, "", hdrCacheControl, ccMaxAge60)(writer, req)
		})
		viaB := viaA.WithNext(srv)

		done := make(chan error)

		go func() {
			res, err := viaA.RoundTrip(newRequest(http.MethodGet, testURL))
			if err == nil {
				_, err = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
			}

			done <- err
		}()

		synctest.Wait()
		roundTrip(t, viaB, newRequest(http.MethodPost, testURL))
		close(release)

		err := <-done
		if err != nil {
			t.Fatal(err)
		}

		get(t, viaA, testURL)
		wantHits(t, srv, 3)
	})
}

func TestWithNextSharesOptions(t *testing.T) {
	t.Parallel()

	// A shared cache doesn't store a private response, whichever Transport it
	// arrives through.
	cache, srv := newTestCache(t, respond(http.StatusOK, bodyHello, hdrCacheControl, "private, max-age=60"), WithShared())
	derived := cache.WithNext(srv)

	get(t, derived, testURL)
	get(t, derived, testURL)
	wantHits(t, srv, 2)
}

func TestWithNextCloseIdleConnections(t *testing.T) {
	t.Parallel()

	first, second := new(idleCloser), new(idleCloser)

	cache, err := New(first)
	if err != nil {
		t.Fatal(err)
	}

	cache.WithNext(second).CloseIdleConnections()

	if first.closed || !second.closed {
		t.Errorf("closed idle connections of the first next: %t, the second: %t; want only the second",
			first.closed, second.closed)
	}
}
