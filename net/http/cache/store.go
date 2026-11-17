package cache

import (
	"bytes"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// maxStatus is the largest valid status code (RFC 9110 §15).
const maxStatus = 599

// storable reports whether RFC 9111 §3 permits storing candidate, and
// whether storing it is useful.
func storable(candidate *variant, shared bool) bool {
	switch {
	case !storableStatus(candidate.status, candidate.cc),
		shared && !sharedMayStore(candidate),
		!worthStoring(candidate):
		return false
	}

	return markedStorable(candidate, shared)
}

// storableStatus applies the rules of §3 on status codes and no-store: the
// status must be final, and understood if it is 206 or 304 or must-understand
// is present, and no-store must be absent unless must-understand overrides it
// (§5.2.2.3).
func storableStatus(status int, dirs directives) bool {
	switch {
	case status < http.StatusOK || status > maxStatus:
		return false
	case !understood(status) &&
		(status == http.StatusPartialContent || status == http.StatusNotModified || dirs.mustUnderstand):
		return false
	}

	return !dirs.noStore || dirs.mustUnderstand
}

// sharedMayStore applies the rules of §3 for a shared cache: no private
// directive, and an Authorization field in the request only with public,
// must-revalidate, or s-maxage (§3.5).
func sharedMayStore(candidate *variant) bool {
	dirs := candidate.cc
	if dirs.private {
		return false
	}

	return !candidate.authorized || dirs.public || dirs.mustRevalidate || dirs.sMaxAge.set
}

// worthStoring reports whether a stored response could ever be reused. One
// that varies on "*", or that has neither freshness nor a validator, couldn't.
func worthStoring(candidate *variant) bool {
	return !candidate.varyStar && (candidate.lifetime > 0 || candidate.hasValidator())
}

// markedStorable reports whether a response has one of the properties that §3
// requires of a stored response: Expires, max-age, s-maxage in a shared
// cache, or what allows a heuristic lifetime.
func markedStorable(candidate *variant, shared bool) bool {
	dirs := candidate.cc

	return len(candidate.header.Values("Expires")) > 0 || dirs.maxAge.set || shared && dirs.sMaxAge.set ||
		heuristicAllowed(candidate.status, dirs, shared)
}

// understood reports whether this cache implements the caching rules of a
// status code. These are the final status codes RFC 9110 §15 defines, except
// 206, because ranges aren't stored, 304, and the unused 305, 306, and 418.
func understood(status int) bool {
	switch {
	case http.StatusOK <= status && status <= http.StatusResetContent,
		http.StatusMultipleChoices <= status && status <= http.StatusSeeOther,
		status == http.StatusTemporaryRedirect, status == http.StatusPermanentRedirect,
		http.StatusBadRequest <= status && status <= http.StatusExpectationFailed,
		status == http.StatusMisdirectedRequest, status == http.StatusUnprocessableEntity,
		status == http.StatusUpgradeRequired,
		http.StatusInternalServerError <= status && status <= http.StatusHTTPVersionNotSupported:
		return true
	}

	return false
}

// storedHeader returns a copy of a received header for storage, without the
// hop-by-hop fields, including those listed in Connection (RFC 9110 §7.6.1),
// which RFC 9111 §3.1 lets a cache drop, or the proxy fields, which §3.1
// forbids storing. Unrecognized fields are kept.
func storedHeader(received http.Header) http.Header {
	out := received.Clone()
	if out == nil {
		out = make(http.Header)
	}

	for _, line := range received.Values("Connection") {
		for name := range strings.SplitSeq(line, ",") {
			if name = strings.Trim(name, " \t"); name != "" {
				out.Del(name)
			}
		}
	}

	// The hop-by-hop fields of RFC 9110 §7.6.1, which RFC 9111 §3.1 lets a
	// cache drop at storage, and the proxy fields that §3.1 forbids storing.
	for _, name := range [...]string{
		"Connection",
		"Keep-Alive",
		"Proxy-Connection",
		"TE",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Authenticate",
		"Proxy-Authentication-Info",
		"Proxy-Authorization",
	} {
		out.Del(name)
	}

	return out
}

// updatedHeader returns stored with each field of a 304 or HEAD response
// replacing the stored one (RFC 9111 §3.2), except fields excepted from
// storage, Content-Length, and Content-Range, which describes a partial
// response. Content-Encoding is kept when the stored body was decoded, since
// a new one wouldn't describe it.
//
// The stored Age is dropped too: it described the age of the original
// response, and the updated one is as old as the 304 or HEAD response.
func updatedHeader(stored, received http.Header, decoded bool) http.Header {
	out := stored.Clone()
	out.Del("Age")

	for name, values := range storedHeader(received) {
		switch name = http.CanonicalHeaderKey(name); name {
		case "Content-Length", "Content-Range":
			continue
		case "Content-Encoding":
			if decoded {
				continue
			}
		}

		out[name] = values
	}

	return out
}

// captureBody passes a response body through to the caller and keeps a copy,
// which it passes to commit once the body is complete (RFC 9111 §3.3): when
// Content-Length bytes have arrived, or at EOF if the length is unknown. An
// early Close, a read error, or a body over the size limit discards the copy
// without affecting the stream.
//
// Like the bodies of Go's Transport, it allows Close to be called while a
// Read is in progress.
type captureBody struct {
	io.ReadCloser

	limit  int64
	want   int64 // the Content-Length, or -1 if unknown
	commit func(body []byte)

	mu   sync.Mutex
	buf  []byte
	done bool

	// A copy of unknown length longer than captureStart is kept in chunks:
	// the full ones, and the bytes they hold, come before buf.
	chunks [][]byte
	held   int
}

func (b *captureBody) Read(dst []byte) (int, error) {
	read, err := b.ReadCloser.Read(dst)

	b.mu.Lock()
	b.capture(dst[:read], err, err == io.EOF)
	b.mu.Unlock()

	// A body wrapper returns the underlying error unchanged. Callers compare
	// it with ==: httputil.ReverseProxy, for one, checks for io.EOF and
	// context.Canceled that way.
	return read, err //nolint:wrapcheck // see above
}

func (b *captureBody) Close() error {
	b.mu.Lock()
	b.discard()
	b.mu.Unlock()

	// Like Read, Close returns the underlying error unchanged.
	return b.ReadCloser.Close() //nolint:wrapcheck // see above
}

// capture adds data, from one Read that returned err, to the copy, and
// commits or discards the copy when the body ends. atEOF reports that err is
// io.EOF itself: a wrapped EOF is a failure, not the end of the body. b.mu
// must be held.
func (b *captureBody) capture(data []byte, err error, atEOF bool) {
	if b.done {
		return
	}

	if int64(b.held+len(b.buf)+len(data)) > b.limit {
		b.discard()

		return
	}

	b.add(data)

	switch length := int64(b.held + len(b.buf)); {
	case err != nil && !atEOF, b.want >= 0 && length > b.want:
		b.discard()
	case length == b.want, b.want < 0 && atEOF:
		// Commit before returning the last bytes. A proxy forwards them
		// before it reads EOF, and its client can send the next request
		// as soon as the response is complete.
		b.commit(b.copied())
		b.discard()
	case atEOF:
		// The body ended before its Content-Length.
		b.discard()
	}
}

// add appends data to the copy. A copy of known length grows toward it (see
// growCapture). One of unknown length grows the same way up to captureStart,
// and after that in chunks of up to captureStart, so that its bytes are
// copied once more, by copied, rather than each time it grows.
func (b *captureBody) add(data []byte) {
	if b.want >= 0 || len(b.chunks) == 0 && len(b.buf)+len(data) <= captureStart {
		b.buf = append(growCapture(b.buf, len(data), b.bound()), data...)

		return
	}

	for len(data) > 0 {
		if len(b.buf) == cap(b.buf) {
			if len(b.buf) > 0 {
				b.chunks = append(b.chunks, b.buf)
				b.held += len(b.buf)
			}

			// capture has checked that data fits in the limit, so the
			// chunk has room for some of it.
			b.buf = make([]byte, 0, min(captureStart, b.limit-int64(b.held)))
		}

		n := copy(b.buf[len(b.buf):cap(b.buf)], data)
		b.buf, data = b.buf[:len(b.buf)+n], data[n:]
	}
}

// copied returns the complete copy, without the spare capacity that a copy
// of unknown length leaves.
func (b *captureBody) copied() []byte {
	if len(b.chunks) == 0 {
		if cap(b.buf) > len(b.buf) {
			return bytes.Clone(b.buf)
		}

		return b.buf
	}

	body := make([]byte, 0, b.held+len(b.buf))
	for _, chunk := range b.chunks {
		body = append(body, chunk...)
	}

	return append(body, b.buf...)
}

func (b *captureBody) discard() {
	b.buf, b.chunks, b.held, b.done = nil, nil, 0, true
}

// bound returns the most that buf grows to: the Content-Length if it's known,
// and otherwise captureStart, after which add keeps the copy in chunks, or
// the size limit if that is smaller.
func (b *captureBody) bound() int64 {
	if b.want >= 0 {
		return b.want
	}

	return min(captureStart, b.limit)
}

const (
	// captureStart is the most a captureBody allocates for its copy before
	// any of the body has arrived. A copy of unknown length longer than that
	// is kept in chunks of at most this size.
	captureStart = 64 << 10

	// captureGrowth is how many times larger growCapture makes the copy. A
	// larger factor copies a large body fewer times, and a smaller one keeps
	// the copy closer to the size of what has arrived.
	captureGrowth = 4
)

// growCapture returns buf with room for n more bytes. It grows the capacity
// by at least captureGrowth times, so a large body is copied only a few times,
// but no further than bound, the Content-Length if it's known, so a complete
// body fills its copy exactly. A body therefore holds at most captureStart
// bytes, or about captureGrowth times what has arrived, however long it says
// it is.
func growCapture(buf []byte, n int, bound int64) []byte {
	need := len(buf) + n
	if need <= cap(buf) {
		return buf
	}

	// The sizes are int64 because captureGrowth times the capacity can
	// overflow an int on a 32-bit platform.
	size := max(captureGrowth*int64(cap(buf)), int64(need))
	size = min(size, max(bound, int64(need)), math.MaxInt)

	grown := make([]byte, len(buf), size)
	copy(grown, buf)

	return grown
}

// store arranges for a response to a GET request to be stored once its body
// has been read, if RFC 9111 §3 allows it.
func (t *Transport) store(req *http.Request, key string, gen uint64, trip exchange) {
	res := trip.res
	if res.ContentLength > t.maxBodySize {
		return
	}

	candidate := newVariant(req, trip, t.shared)
	if !storable(candidate, t.shared) {
		return
	}

	commit := func(body []byte) {
		candidate.body = body
		t.put(key, gen, candidate)
	}

	if res.ContentLength == 0 {
		// The caller might close an empty body without reading it.
		commit(nil)

		return
	}

	res.Body = &captureBody{
		ReadCloser: res.Body,
		limit:      t.maxBodySize,
		want:       res.ContentLength,
		commit:     commit,
		mu:         sync.Mutex{},
		buf:        make([]byte, 0, min(max(res.ContentLength, 0), captureStart)),
		done:       false,
		chunks:     nil,
		held:       0,
	}
}

// put stores added unless it is larger than WithMaxBytes, or key may have been
// invalidated since gen was read.
func (t *Transport) put(key string, gen uint64, added *variant) {
	// fitBytes would remove a response this large, but only after withVariant
	// had let it take the place of a stored one.
	if added.size() > t.maxBytes {
		return
	}

	guard := t.stripe(key)
	guard.mu.Lock()
	defer guard.mu.Unlock()

	if guard.invalidatedSince(key, gen) {
		return
	}

	var old []*variant
	if stored, found := t.entries.Get(key); found {
		old = stored.variants
	}

	t.set(key, withVariant(old, added, t.limits))
}

// freshen applies a 304 response to req to the stored responses that it
// identifies (RFC 9111 §4.3.4). sent is the stored response that the request
// validated, or nil if the preconditions were the client's. If sent is set,
// freshen returns the updated response to serve for req, or nil if none was
// identified.
//
// As applyUpdates describes, it may store only some of the updates, but the
// result is valid for req either way. See updateVariant for an update that
// may not be stored, or that doesn't validate the stored response.
func (t *Transport) freshen(req *http.Request, key string, gen uint64, trip exchange, sent *variant) *variant {
	guard := t.stripe(key)
	guard.mu.Lock()
	defer guard.mu.Unlock()

	stored, found := t.entries.Get(key)
	if !found {
		return nil
	}

	ids := stored.identify(req, trip.res.Header, sent)
	if len(ids) == 0 {
		return nil
	}

	// identify matched the 304's validators to the stored responses, or the
	// request carried sent's. A 304 with neither, to the client's own
	// preconditions, says nothing about the response it updates.
	validated := sent != nil || validatorsOf(trip.res.Header).hasValidator()
	updates := make([]*variant, len(stored.variants))

	var serve *variant

	for _, pos := range ids {
		var updated *variant

		updated, updates[pos] = t.updateVariant(req, trip, stored.variants[pos], validated)
		if serve == nil || preferred(updated, serve) {
			serve = updated
		}
	}

	t.applyUpdates(key, guard.invalidatedSince(key, gen), stored.variants, updates)

	return serve
}

// freshenFromHead applies a 200 response to a HEAD request to each stored GET
// response that could have been chosen for it (RFC 9111 §4.3.5). A response
// that the HEAD describes is updated from its header; any other is marked
// invalid. As applyUpdates describes, it may store only some of the updates.
//
// A HEAD response validates a stored response only if it has a validator,
// which describedBy then requires to match (see updateVariant).
func (t *Transport) freshenFromHead(req *http.Request, key string, gen uint64, trip exchange) {
	guard := t.stripe(key)
	guard.mu.Lock()
	defer guard.mu.Unlock()

	stored, found := t.entries.Get(key)
	if !found {
		return
	}

	header := trip.res.Header
	validated := validatorsOf(header).hasValidator()
	dial := dialHost(req)
	updates := make([]*variant, len(stored.variants))

	for pos, candidate := range stored.variants {
		switch {
		case !candidate.matches(req, dial):
		case candidate.describedBy(header):
			_, updates[pos] = t.updateVariant(req, trip, candidate, validated)
		default:
			updates[pos] = candidate.invalidated()
		}
	}

	t.applyUpdates(key, guard.invalidatedSince(key, gen), stored.variants, updates)
}

// applyUpdates stores key's responses with each non-nil element of updates in
// place of the stored response at its index. The caller holds key's stripe
// lock.
//
// If raced is set, because key may have been invalidated since the request
// was sent, it applies only the updates that mark a response invalid. Any
// other could make a response usable that the unsafe request outdated. One
// that marks it invalid can't, and still has to be stored, so Save doesn't
// write a response that the update withdrew.
func (t *Transport) applyUpdates(key string, raced bool, stored, updates []*variant) {
	variants := slices.Clone(stored)
	changed := false

	for pos, kept := range updates {
		if kept != nil && (!raced || kept.invalid) {
			variants[pos], changed = kept, true
		}
	}

	if changed {
		t.set(key, variants)
	}
}

// updateVariant returns stored updated from a 304 or HEAD response to req,
// and the response to keep in its place.
//
// The updated response is kept only if RFC 9111 §3 allows storing it. An
// update can't be stored if, for example, it adds no-store, or private in a
// shared cache, or if it answers a request with Authorization in a shared
// cache. Then stored is kept but marked invalid and withdrawn, since its
// stored fields may no longer apply.
//
// validated reports that the response shows stored is still current: it has
// a validator that matches stored's, or it is a 304 to the cache's own
// conditional request for stored. Without that, a stored response that must
// be validated, after an unsafe request or Load, is kept as it is.
func (t *Transport) updateVariant(
	req *http.Request, trip exchange, stored *variant, validated bool,
) (*variant, *variant) {
	updated := stored.updated(req, trip, t.shared)

	switch {
	case !storable(updated, t.shared):
		kept := stored.invalidated()
		kept.withdrawn = true

		return updated, kept
	case stored.invalid && !validated:
		return updated, stored
	}

	return updated, updated
}

// invalidate marks every stored response for key invalid (RFC 9111 §4.4) and
// records the invalidation, so responses for key already in flight aren't
// stored.
func (t *Transport) invalidate(key string) {
	guard := t.stripe(key)
	guard.mu.Lock()
	defer guard.mu.Unlock()

	guard.record(key)

	stored, found := t.entries.Get(key)
	if !found {
		return
	}

	variants := make([]*variant, len(stored.variants))

	for pos, candidate := range stored.variants {
		variants[pos] = candidate.invalidated()
	}

	t.set(key, variants)
}

// set stores variants as key's entry, without the ones that don't fit in
// WithMaxBytes together (see fitBytes). The caller holds key's stripe lock.
func (t *Transport) set(key string, variants []*variant) {
	variants = fitBytes(variants, t.maxBytes)

	// Set fails only if the cache can't evict an entry while full, and then
	// leaves key's old entry in place. That entry might hold a response that
	// this update withdrew, so it is removed: not storing a response is
	// always permitted.
	if len(variants) == 0 || t.entries.Set(key, &entry{variants: variants}) != nil {
		t.entries.Delete(key)
	}
}
