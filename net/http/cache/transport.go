package cache

import (
	"fmt"
	"hash/maphash"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.dw1.io/fastcache" //nolint:depguard // depguard has no allowlist without a config
)

const (
	stripeCount = 256

	// recentInvalidations is how many invalidated keys each stripe remembers.
	recentInvalidations = 8
)

// Transport is an [http.RoundTripper] that caches responses as RFC 9111
// describes. It is a private cache unless created with [WithShared].
//
// A Transport is safe for concurrent use by multiple goroutines.
type Transport struct {
	// The Transports that [Transport.WithNext] returns share storage.
	*storage

	next http.RoundTripper
}

// storage holds the stored responses of one or more Transports, with the
// options that govern them and the state that guards and counts them.
type storage struct {
	shared      bool
	maxBodySize int64
	maxBytes    int
	limits      variantLimits
	entries     *fastcache.Cache[string, *entry]

	// Writes to an entry hold its stripe's lock, so an update can't overwrite
	// a concurrent invalidation. Reads don't lock.
	seed    maphash.Seed
	stripes [stripeCount]stripe

	counts counters
}

// stripe guards the writes to the keys that hash to it, and records their
// invalidations. A response is stored only if its key wasn't invalidated
// while its request was in flight, so a response that might predate an unsafe
// request is never stored.
type stripe struct {
	mu sync.Mutex

	// gen counts the invalidations on this stripe. It is written with mu
	// held, and read without it when a request is sent.
	gen atomic.Uint64

	// recent holds the key of invalidation number n at n%len(recent).
	recent [recentInvalidations]string
}

// record records an invalidation of key. s.mu must be held.
func (s *stripe) record(key string) {
	s.recent[s.gen.Add(1)%recentInvalidations] = key
}

// invalidatedSince reports whether key may have been invalidated after
// invalidation number gen. When more invalidations than recent holds have
// happened since, it can't tell, and reports true. s.mu must be held.
func (s *stripe) invalidatedSince(key string, gen uint64) bool {
	now := s.gen.Load()
	if now-gen > recentInvalidations {
		return true
	}

	for n := gen + 1; n <= now; n++ {
		if s.recent[n%recentInvalidations] == key {
			return true
		}
	}

	return false
}

// New returns a Transport that caches the responses of next. If next is nil,
// it uses [http.DefaultTransport].
func New(next http.RoundTripper, opts ...Option) (*Transport, error) {
	if next == nil {
		next = http.DefaultTransport
	}

	cfg := config{
		shared:      false,
		maxEntries:  defaultMaxEntries,
		maxBodySize: defaultMaxBodySize,
		maxVariants: defaultMaxVariants,
		maxBytes:    defaultMaxBytes,
	}

	for _, opt := range opts {
		err := opt(&cfg)
		if err != nil {
			return nil, err
		}
	}

	// A 32-bit platform can't hold more than math.MaxInt bytes anyway.
	maxBytes := int(min(cfg.maxBytes, math.MaxInt))

	entries, err := fastcache.NewWeighted(cfg.maxEntries, maxBytes, weigh)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOption, err)
	}

	return &Transport{
		storage: &storage{
			shared:      cfg.shared,
			maxBodySize: min(cfg.maxBodySize, cfg.maxBytes),
			maxBytes:    maxBytes,
			limits:      newVariantLimits(cfg.maxVariants),
			entries:     entries,
			seed:        maphash.MakeSeed(),
			stripes:     [stripeCount]stripe{},
			counts: counters{
				hits: atomic.Uint64{}, revalidations: atomic.Uint64{}, misses: atomic.Uint64{},
				bypasses: atomic.Uint64{}, stores: atomic.Uint64{}, drops: atomic.Uint64{},
			},
		},
		next: next,
	}, nil
}

// WithNext returns a Transport that sends requests to next instead of t's
// next RoundTripper, and shares t's stored responses, options, and [Stats].
// If next is nil, it uses [http.DefaultTransport].
//
// It lets clients whose transports must differ, for example in their proxy
// settings, share a cache. A response stored through either Transport answers
// requests through the other, and an unsafe request through either
// invalidates stored responses for both.
//
// The cache sees each request before next changes it, so the next
// RoundTrippers that share stored responses must get the same response to
// the same request. They must add the same credentials, if any, such as an
// Authorization field, cookies, or a TLS client certificate. They must reach
// the same origin servers, through any proxies, and verify them alike, for
// example with the same TLS root CAs and InsecureSkipVerify setting. They must
// also handle content codings alike: as [http.Transport]s, they must have the
// same DisableCompression setting. In a private cache, the clients must also
// act for the same user.
func (t *Transport) WithNext(next http.RoundTripper) *Transport {
	if next == nil {
		next = http.DefaultTransport
	}

	return &Transport{storage: t.storage, next: next}
}

// RoundTrip answers req from the cache when RFC 9111 allows it, and
// otherwise sends it to the next RoundTripper, storing or updating responses
// on the way back.
//
// GET and HEAD requests use the cache, except those with a body, a scheme
// other than http or https, no host, or a Range, If-Range, If-Match,
// If-Unmodified-Since, or Upgrade field, which are sent unchanged, or get a
// 504 (Gateway Timeout) response if they have only-if-cached. A non-error
// response to an unsafe or unknown method invalidates the responses
// stored for its target URI. OPTIONS and TRACE requests, which are safe, and
// CONNECT requests, whose target is a host rather than a URI the cache
// stores, pass through.
//
// Every response from the next RoundTripper gets a Date field if it has none
// (RFC 9110 §6.6.1).
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case "", http.MethodGet, http.MethodHead:
		return t.roundTripCached(req)
	case http.MethodOptions, http.MethodTrace, http.MethodConnect:
		return t.forward(req)
	default:
		return t.roundTripUnsafe(req)
	}
}

// CloseIdleConnections closes the idle connections of the next RoundTripper,
// if it has a CloseIdleConnections method.
func (t *Transport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (t *Transport) roundTripCached(req *http.Request) (*http.Response, error) {
	tgt, cacheable := newTarget(req)
	dirs := parseDirectives(req.Header["Cache-Control"])

	if !cacheable || bypass(req) {
		t.counts.bypasses.Add(1)

		// Such a request can't use a stored response, so only-if-cached
		// leaves only a 504 (RFC 9111 §5.2.1.7).
		if dirs.onlyIfCached {
			closeBody(req)

			return gatewayTimeout(req, time.Now()), nil
		}

		return t.forward(req)
	}

	key := tgt.key(req.URL.RequestURI())

	var stored *variant
	if ent, found := t.entries.Get(key); found {
		stored = ent.choose(req)
	}

	now := time.Now()
	if stored != nil {
		if age := stored.currentAge(now); t.reusable(stored, dirs, age) {
			t.counts.hits.Add(1)
			closeBody(req)

			return stored.hit(req, age), nil
		}
	}

	if dirs.onlyIfCached {
		t.counts.misses.Add(1)
		closeBody(req)

		return gatewayTimeout(req, now), nil
	}

	res, revalidated, err := t.fetch(req, key, dirs, stored)
	if revalidated {
		t.counts.revalidations.Add(1)
	} else {
		t.counts.misses.Add(1)
	}

	return res, err
}

// forward sends req to the next RoundTripper without consulting or updating
// the cache.
func (t *Transport) forward(req *http.Request) (*http.Response, error) {
	trip, err := t.send(req)
	if err != nil {
		return nil, err
	}

	return trip.res, nil
}

// bypass reports whether a GET or HEAD request skips the cache: a range
// request (RFC 9111 §3.3), a request with preconditions only an origin
// evaluates (§4.3.2), a protocol upgrade, or a request with a body.
func bypass(req *http.Request) bool {
	if req.ContentLength != 0 || req.Body != nil && req.Body != http.NoBody {
		return true
	}

	// Indexing the header with canonical names skips the canonicalization that
	// Header.Values repeats on every call, which adds up on the hit path.
	for _, name := range [...]string{"Range", "If-Range", "If-Match", "If-Unmodified-Since", "Upgrade"} {
		if len(req.Header[name]) > 0 {
			return true
		}
	}

	return false
}

// reusable reports whether a stored response, at the given age, can answer
// a request with directives dirs without contacting the origin (RFC 9111 §4).
func (t *Transport) reusable(stored *variant, dirs directives, age time.Duration) bool {
	switch {
	case stored.invalid, stored.cc.noCache, dirs.noCache:
		return false
	case dirs.maxAge.set && age > dirs.maxAge.d:
		return false
	case dirs.minFresh.set && stored.lifetime-age < dirs.minFresh.d:
		return false
	case age < stored.lifetime:
		return true
	}

	return t.staleAllowed(stored, dirs, age)
}

// staleAllowed reports whether a stale stored response, at the given age, can
// answer a request with directives dirs. Only the client can permit it
// (§4.2.4), and some response directives forbid it (§5.2.2.2, §5.2.2.8,
// §5.2.2.10).
func (t *Transport) staleAllowed(stored *variant, dirs directives, age time.Duration) bool {
	forbidden := stored.cc.mustRevalidate || t.shared && (stored.cc.proxyRevalidate || stored.cc.sMaxAge.set)

	return dirs.maxStale.set && !forbidden && age-stored.lifetime <= dirs.maxStale.d
}

// fetch forwards a GET or HEAD request that the cache can't answer, as a
// conditional request when the stored response can be validated. It reports
// whether a 304 response let it answer with the stored response.
func (t *Transport) fetch(
	req *http.Request, key string, dirs directives, stored *variant,
) (*http.Response, bool, error) {
	gen := t.stripe(key).gen.Load()

	// A client's own preconditions are forwarded unchanged rather than merged
	// with the cache's, and a 304 to a no-store request couldn't update the
	// stored response.
	if stored != nil && stored.hasValidator() && !dirs.noStore && !hasConditional(req) {
		trip, err := t.send(withValidators(req, stored))
		if err != nil {
			return nil, false, err
		}

		trip.res.Request = req
		if trip.res.StatusCode != http.StatusNotModified {
			return t.handle(req, key, gen, trip), false, nil
		}

		_ = trip.res.Body.Close()

		// A 304 that identifies no stored response (§4.3.4), for example
		// because its strong validator matches none, can't complete this
		// unconditional request, so the request is sent again without
		// validators.
		if updated := t.freshen(req, key, gen, trip, stored); updated != nil {
			return updated.response(req, updated.header.Clone()), true, nil
		}
	}

	trip, err := t.send(req)
	if err != nil {
		return nil, false, err
	}

	if dirs.noStore {
		// §5.2.1.5: nothing from this exchange may be stored.
		return trip.res, false, nil
	}

	return t.handle(req, key, gen, trip), false, nil
}

// handle applies a response from the origin to the stored responses and
// returns it for the caller.
func (t *Transport) handle(req *http.Request, key string, gen uint64, trip exchange) *http.Response {
	switch {
	case trip.res.StatusCode == http.StatusNotModified:
		// The 304 answers the client's own preconditions, and passes through.
		t.freshen(req, key, gen, trip, nil)
	case req.Method == http.MethodHead:
		if trip.res.StatusCode == http.StatusOK {
			t.freshenFromHead(req, key, gen, trip)
		}
	default:
		t.store(req, key, gen, trip)
	}

	return trip.res
}

// roundTripUnsafe forwards a request with an unsafe or unknown method. A
// non-error response invalidates the target URI and, if they have the same
// origin, the URIs in Location and Content-Location (RFC 9111 §4.4).
func (t *Transport) roundTripUnsafe(req *http.Request) (*http.Response, error) {
	trip, err := t.send(req)
	if err != nil {
		return nil, err
	}

	if code := trip.res.StatusCode; code < http.StatusOK || code >= http.StatusBadRequest {
		return trip.res, nil
	}

	tgt, cacheable := newTarget(req)
	if !cacheable {
		return trip.res, nil
	}

	t.invalidate(tgt.key(req.URL.RequestURI()))

	for _, name := range [...]string{"Location", "Content-Location"} {
		if key, sameOrigin := tgt.resolve(req, trip.res.Header.Get(name)); sameOrigin {
			t.invalidate(key)
		}
	}

	return trip.res, nil
}

// exchange is one request forwarded to the next RoundTripper and the response
// to it, with the times that age calculations need (RFC 9111 §4.2.3).
type exchange struct {
	res          *http.Response
	requestTime  time.Time
	responseTime time.Time
}

// send forwards req to the next RoundTripper and records the request and
// response times.
func (t *Transport) send(req *http.Request) (exchange, error) {
	requestTime := time.Now()

	// The response goes to the caller, which closes its body.
	res, err := t.next.RoundTrip(req) //nolint:bodyclose // see above
	if err != nil {
		// RoundTrip returns the next RoundTripper's error unchanged.
		return exchange{res: nil, requestTime: requestTime, responseTime: requestTime}, err //nolint:wrapcheck // see above
	}

	return newExchange(res, requestTime, time.Now()), nil
}

// newExchange records a response from the next RoundTripper and adds a Date
// field if it has none (RFC 9110 §6.6.1).
func newExchange(res *http.Response, requestTime, responseTime time.Time) exchange {
	if res.Header == nil {
		res.Header = make(http.Header)
	}

	if len(res.Header.Values("Date")) == 0 {
		res.Header.Set("Date", formatHTTPDate(responseTime))
	}

	return exchange{res: res, requestTime: requestTime, responseTime: responseTime}
}

func (t *Transport) stripe(key string) *stripe {
	return &t.stripes[t.stripeIndex(key)]
}

func (t *Transport) stripeIndex(key string) uint64 {
	return maphash.String(t.seed, key) % stripeCount
}

// closeBody closes the body of a request that the cache answers itself, as
// the RoundTripper contract requires.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
