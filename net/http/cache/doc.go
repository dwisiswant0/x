// Package cache provides an RFC 9111 HTTP cache as an [http.RoundTripper].
// It keeps responses in memory.
//
// [New] wraps another RoundTripper. The result is a private cache, for one
// user's [http.Client]:
//
//	transport, err := cache.New(nil)
//	if err != nil {
//		// handle err
//	}
//	client := &http.Client{Transport: transport}
//
// [WithShared] makes it a shared cache, for a proxy such as
// [httputil.ReverseProxy] that serves many users. Give a shared cache an
// [http.Transport] with DisableCompression set as its next RoundTripper, so
// that it doesn't decode gzip responses and the proxy forwards content
// unchanged (RFC 9110 §7.7):
//
//	transport, err := cache.New(&http.Transport{DisableCompression: true}, cache.WithShared())
//
// [Transport.WithNext] lets clients whose transports must differ, for example
// in their proxy settings, share stored responses.
//
// # Conformance
//
// The package's tests list each MUST and SHOULD of RFC 9111, and of the parts
// of RFC 9110 that the cache relies on, such as dates, validators, and
// conditional requests, with the test that covers it, or the reason it doesn't
// apply or isn't met. They fail if a requirement loses its test. Of the
// requirements that bind a cache, it meets all but one SHOULD: when
// must-revalidate forbids a stale response and the origin can't be reached,
// RoundTrip returns the next RoundTripper's error rather than a 504 (RFC 9111
// §5.2.2.2).
//
// Against the http-tests/cache-tests suite (https://cache-tests.fyi), at its
// commit 7e2c537 of 2026-11-04, the cache gets these results for 366 tests:
//
//	Result                      Tests
//	Passed                        224
//	Failed, required                4
//	Failed, optional               19
//	Behavior check: yes            59
//	Behavior check: no             30
//	Not run, dependency failed     25
//	Setup failed                    4
//	Cache retried a request         1
//
// The required failures are the four tests of CDN-Cache-Control, which RFC
// 9213 §2.2 forbids a cache without CDN-Cache-Control on its target list from
// honoring. The tests that didn't run include required tests of optional
// features that the cache leaves out, such as stale-while-revalidate and
// partial content. TestCacheTests in the package's tests runs the suite when
// CACHE_TESTS_DIR names a clone of it.
//
// # What is cached
//
// The cache stores only responses to GET requests, and uses them to answer
// both GET and HEAD requests. A GET or HEAD request skips the cache and goes
// to the next RoundTripper unchanged if it has a body, a scheme other than
// http or https, no host, or any of these fields: Range, If-Range, If-Match,
// If-Unmodified-Since, Upgrade. If it also has only-if-cached, it gets a 504
// (Gateway Timeout) response instead.
//
// The cache doesn't store a 206 response, a body that ends early, a body
// larger than [WithMaxBodySize], a response with "Vary: *", or a response
// that has neither freshness nor a validator and so could never be reused.
//
// A Set-Cookie field doesn't prevent storing a response (RFC 9111 §7.3). An
// origin that sets a cookie for one user on a cacheable response should mark
// it private or no-store, especially for a shared cache.
//
// Responses are keyed by target URI: scheme, host, port, path, and query. A
// response to a request whose Host differs from its URL.Host is reused only
// for requests sent to the same URL.Host, so backends that share a Host header
// don't share responses. Invalidation still applies to every stored response
// for the target URI.
//
// # Choices the RFC leaves open
//
//   - A response without explicit expiration is fresh for 10% of the time
//     since its Last-Modified date, if its status is heuristically cacheable or
//     it is marked public, or private in a private cache.
//   - A stale response is served only when the request's max-stale allows it.
//     When the origin can't be reached, RoundTrip returns the error from the
//     next RoundTripper and never a stale response.
//   - Extension directives, such as stale-while-revalidate and immutable, and
//     targeted fields such as CDN-Cache-Control (RFC 9213) are ignored.
//   - The qualified forms of no-cache and private, which list field names,
//     count as unqualified.
//   - Hop-by-hop fields, the fields that Connection lists, and trailers aren't
//     stored. An invalid Date is replaced with the time the response arrived.
//   - A non-error response to an unsafe method also invalidates the URIs in
//     Location and Content-Location, if they have the same origin.
//   - A client's If-None-Match or If-Modified-Since is evaluated against a
//     reusable stored response, and only a stored 200 can produce a 304.
//     Without a reusable response, the request is forwarded with the client's
//     preconditions unchanged rather than merged with the cache's own
//     validators.
//   - A 304 without validators that answers the cache's own conditional request
//     validates the stored response that request named. RFC 9110 §15.4.5
//     requires a 304 to carry the ETag that a 200 would, but some servers
//     omit it.
//   - A stored response that must be validated, after an unsafe request or
//     Load, is usable again only after a response with a validator that
//     matches it, or a 304 to the cache's own conditional request. A 304 to a
//     client's own preconditions, or a HEAD response, without validators
//     leaves it invalid.
//   - A 304 or HEAD response that RFC 9111 §3 wouldn't let the cache store,
//     such as one marked no-store, updates no stored response. The stored
//     response it would have updated must be validated before its next use.
//   - Concurrent requests for the same target URI aren't collapsed: each miss
//     goes to the origin.
//   - The cache neither honors nor generates Pragma or Warning.
//
// # Snapshots
//
// [Transport.Save] writes the stored responses that can be validated to a
// snapshot, and [Transport.Load] adds the responses in a snapshot to a
// Transport, for example to keep a proxy's cache across restarts. Every
// loaded response is validated with the origin before its first use, so one
// that an unsafe request invalidated after the snapshot was saved can't come
// back as fresh (RFC 9111 §4.4). A 304 then lets the cache serve the loaded
// body without fetching it again.
//
// Load stores a response only if RFC 9111 §3 lets the loading Transport store
// it. A shared cache, for example, skips responses marked private, and
// responses to requests with Authorization unless public, must-revalidate, or
// s-maxage allows it (RFC 9111 §3.5). Save never writes a response marked
// no-store, nor one whose last update the cache couldn't store, as when the
// update added no-store.
//
// A snapshot holds whole responses, which in a private cache can include
// responses meant for one user. Keep it as private as they are, and load only
// snapshots from a trusted source: for example, a file that only its owner
// can read and write.
//
// # Memory
//
// The cache holds up to [WithMaxBytes] of responses, 64 MiB by default,
// counting their bodies, their header fields, and the request fields that their
// Vary headers name. Memory use is higher, because the count leaves out Go's
// own overhead. When a response doesn't fit, the target URIs stored first are
// evicted until it does, and a target URI whose responses don't fit together
// drops its oldest ones.
//
// Within that, it holds up to [WithMaxEntries] target URIs, each with up to
// [WithMaxVariants] responses from one server that differ by their Vary
// fields. A proxy that sends requests for one Host to several servers stores
// up to 8 times as many per target URI, 64 by default.
//
// Each response that is being read and might be stored also buffers up to
// [WithMaxBodySize] bytes, or the WithMaxBytes limit if that is smaller, until
// it ends. Those bytes count toward that limit only once the response is
// stored.
//
// [Transport.Stats] counts the target URIs evicted and the responses dropped,
// which shows whether the limits are too small for a workload.
//
// # Performance
//
// A hit takes no lock, except to recheck a lookup that raced the removal of
// another target URI, and it serves the stored body in place, so it costs the
// same for any body size. A request for a target URI whose responses vary is
// compared with each of them, so it costs more the more responses are stored
// for it (see [WithMaxVariants]).
//
// A miss copies the body as the caller reads it, and stores it once the body
// ends. A body whose length is unknown, as when Go's Transport decodes gzip,
// costs more: its copy can't be sized in advance, and is copied once more
// when the body ends. Past 64 KiB, storing it allocates 2 to 3 times its
// size.
//
// Storing a response for a new target URI, or one that makes a target URI's
// responses larger, holds a lock across the whole cache while it evicts
// what no longer fits. A response much larger than most can evict many target
// URIs at once and delay other stores while it does, though not hits.
// Concurrent misses for one target URI each go to the next RoundTripper, as
// listed above.
//
// [Transport.Save] locks each part of the cache only while it copies
// references to the responses there, so requests continue while it writes the
// snapshot.
//
// On an Apple M5 Pro with Go 1.27, and an origin that answers from memory,
// the benchmarks in the package's tests measure:
//
//	Request                            Benchmark             Time     Allocations
//	Hit, 1 KiB body                    RoundTrip/hit         0.42 µs  6
//	Hit among 4 responses that vary    RoundTrip/vary-hit    0.60 µs  6
//	Miss that stores a 1 KiB response  RoundTrip/miss-store  2.4 µs   20
//
// Their stored responses have 2 header fields, or 3 with Vary. A hit copies
// the stored header for its response, so each field adds to its time.
// Run go test -bench RoundTrip to measure them on your machine.
//
// [httputil.ReverseProxy]: https://pkg.go.dev/net/http/httputil#ReverseProxy
package cache
