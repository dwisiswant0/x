package cache

import (
	"sync/atomic"

	"go.dw1.io/fastcache" //nolint:depguard // depguard has no allowlist without a config
)

// Stats holds counts of what a [Transport] has done since [New] created it,
// together with the Transports that share its stored responses through
// [Transport.WithNext]. They show how often the cache answers requests, and
// whether its limits are too small for a workload.
//
// Each GET and HEAD request counts in exactly one of Hits, Revalidations,
// Misses, and Bypasses. Requests with other methods aren't counted.
type Stats struct {
	// Hits counts the requests answered with a stored response without
	// contacting the origin.
	Hits uint64

	// Revalidations counts the requests answered with a stored response
	// after the origin validated it with a 304 (Not Modified).
	Revalidations uint64

	// Misses counts the requests that no stored response could answer. The
	// cache sent them to the next RoundTripper or, for only-if-cached,
	// answered with a 504 (Gateway Timeout).
	Misses uint64

	// Bypasses counts the requests that skipped the cache, as described under
	// "What is cached" in the package documentation.
	Bypasses uint64

	// Stores counts the responses stored, including those that
	// [Transport.Load] added.
	Stores uint64

	// Evictions counts the target URIs evicted, each with all its responses,
	// to make room within [WithMaxEntries] and [WithMaxBytes].
	Evictions uint64

	// Drops counts the responses dropped on their own, rather than evicted
	// with their target URI, to fit [WithMaxVariants] or [WithMaxBytes].
	Drops uint64
}

// counters holds the counts that Stats reports, except Evictions, which
// fastcache counts.
type counters struct {
	hits          atomic.Uint64
	revalidations atomic.Uint64
	misses        atomic.Uint64
	bypasses      atomic.Uint64
	stores        atomic.Uint64
	drops         atomic.Uint64
}

// addDrops counts n dropped responses.
func (c *counters) addDrops(n int) {
	c.drops.Add(uint64(n)) //nolint:gosec // n counts responses, so it isn't negative
}

// Stats returns what t, and the Transports that share its stored responses,
// have counted so far. It reads each count separately, so while requests are
// in flight, the counts may not all describe the same moment.
func (t *Transport) Stats() Stats {
	var evicted fastcache.Stats

	t.entries.UpdateStats(&evicted)

	return Stats{
		Hits:          t.counts.hits.Load(),
		Revalidations: t.counts.revalidations.Load(),
		Misses:        t.counts.misses.Load(),
		Bypasses:      t.counts.bypasses.Load(),
		Stores:        t.counts.stores.Load(),
		Evictions:     evicted.Evictions,
		Drops:         t.counts.drops.Load(),
	}
}
