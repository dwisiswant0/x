package cache

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"go.dw1.io/fastcache" //nolint:depguard // depguard has no allowlist without a config
)

// snapshotMagic starts a snapshot and names its format and version, and Load
// rejects any other. The data that fastcache.SaveToFunc writes follows: the
// target URIs oldest first, each with its responses as a []snapshotResponse.
// Load gets an error from fastcache for a truncated snapshot, or for damage
// that would change a response.
const snapshotMagic = "go.dw1.io/x/net/http/cache snapshot v1\n"

// snapshotResponse is one stored response. Load recomputes the fields that
// derive computes from its header, for the mode of the loading Transport.
type snapshotResponse struct {
	Status       int
	StatusText   string
	Header       http.Header
	Body         []byte
	Decoded      bool
	Authorized   bool
	RequestTime  time.Time
	ResponseTime time.Time

	Vary     []snapshotVaryField
	DialHost string
}

type snapshotVaryField struct {
	Name    string
	Value   string
	Present bool
}

// Save writes the responses that t has stored to w, as a snapshot that
// [Transport.Load] can read back. It writes only responses that can be
// validated, including those that t must validate before their next use,
// such as responses that Load added and no request has used yet. It writes
// none that has a no-store directive, which RFC 9111 §5.2.2.5 forbids keeping
// in non-volatile storage, nor one whose last update t couldn't store, as
// when the update added no-store.
//
// Save writes target URIs oldest first, so a Transport that loads the
// snapshot evicts them in the order t would. The snapshot is compressed.
//
// A snapshot holds whole responses. A private cache stores responses meant
// for one user, including responses to requests with an Authorization field,
// so keep a snapshot as private as those responses, and let only its owner
// write it: see [Transport.Load].
//
// Save doesn't stop t from handling requests. A response stored or updated
// while Save runs may be in the snapshot as it was before, including one
// whose update t couldn't store.
func (t *Transport) Save(w io.Writer) error {
	_, err := io.WriteString(w, snapshotMagic)
	if err == nil {
		err = fastcache.SaveToFunc(t.entries, w, snapshotResponses)
	}

	if err != nil {
		return fmt.Errorf("cache: saving snapshot: %w", err)
	}

	return nil
}

// Load adds the responses in a snapshot that [Transport.Save] wrote to t.
//
// Every loaded response must be validated with the origin before its first
// use, so a response that an unsafe request invalidated after the snapshot was
// saved can't come back as fresh (RFC 9111 §4.4). A 304 response to that
// validation lets the cache serve the loaded body without fetching it again.
//
// A response is added only if RFC 9111 §3 lets t store it with the options
// t was created with. A shared cache doesn't load a response marked private,
// for example, nor one whose body a private cache stored decoded. No response
// larger than [WithMaxBodySize] or [WithMaxBytes] is loaded, nor a response
// damaged since it was saved.
//
// When t already stores a response for the same request fields and server,
// Load keeps t's and skips the snapshot's. Otherwise loaded responses count
// against the cache's limits like any others: loading more target URIs than
// [WithMaxEntries] allows evicts the ones stored first, which are those t
// stored before Load and then the oldest in the snapshot. The limits on
// responses per target URI, from [WithMaxVariants] and [WithMaxBytes], can
// drop older stored responses, including ones stored before Load.
//
// Load trusts the snapshot for what it can't check, such as whether a
// response answered a request with an Authorization field, so load only
// snapshots from a trusted source. Snapshots are gob-encoded, and
// [encoding/gob] isn't hardened against hostile input either.
//
// Load returns an error that wraps [ErrInvalidSnapshot] if reading r fails, or
// if r doesn't hold a snapshot or holds only part of one. It stops at the first
// error, and keeps the responses it has added.
func (t *Transport) Load(r io.Reader) error {
	magic := make([]byte, len(snapshotMagic))

	_, err := io.ReadFull(r, magic)
	if err == nil && string(magic) == snapshotMagic {
		err = fastcache.LoadFromFunc(r, func(key string, responses []snapshotResponse) error {
			t.restore(key, responses)

			return nil
		})
	}

	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	case string(magic) != snapshotMagic:
		return fmt.Errorf("%w: starts with %q", ErrInvalidSnapshot, magic)
	}

	return nil
}

// restore adds the responses saved for key that t can store.
func (t *Transport) restore(key string, responses []snapshotResponse) {
	guard := t.stripe(key)
	guard.mu.Lock()
	defer guard.mu.Unlock()

	var variants []*variant
	if stored, found := t.entries.Get(key); found {
		variants = stored.variants
	}

	added := false

	for _, response := range responses {
		restored, valid := response.variant(t.shared)
		if !valid || !t.loadable(restored) || slices.ContainsFunc(variants, restored.sameSelection) {
			continue
		}

		variants = withVariant(variants, restored, t.limits)
		added = true
	}

	if added {
		t.set(key, variants)
	}
}

// loadable reports whether t can store a response from a snapshot: one that
// RFC 9111 §3 lets it store, within its body limit, that can be validated
// before use. A shared cache doesn't load a body that a private cache
// decoded, which would be transformed content (RFC 9110 §7.7).
func (t *Transport) loadable(restored *variant) bool {
	return (!t.shared || !restored.decoded) && int64(len(restored.body)) <= t.maxBodySize &&
		restored.hasValidator() && storable(restored, t.shared)
}

// snapshotResponses returns the responses of ent that Save writes, and
// reports whether there are any, so that Save skips a target URI with none.
func snapshotResponses(_ string, ent *entry) ([]snapshotResponse, bool) {
	responses := make([]snapshotResponse, 0, len(ent.variants))

	for _, stored := range ent.variants {
		// A response stored despite no-store, because must-understand
		// overrides it (RFC 9111 §5.2.2.3), still can't be written. Neither
		// can a withdrawn one, whose update might have said no-store, nor one
		// that couldn't be validated after Load. A response that is only
		// invalid is written, since Load marks every response invalid.
		if stored.cc.noStore || stored.withdrawn || !stored.hasValidator() {
			continue
		}

		vary := make([]snapshotVaryField, len(stored.vary))
		for pos, field := range stored.vary {
			vary[pos] = snapshotVaryField{Name: field.name, Value: field.value, Present: field.present}
		}

		response := snapshotResponse{
			Status:       stored.status,
			StatusText:   stored.statusText,
			Header:       stored.header,
			Body:         stored.body,
			Decoded:      stored.decoded,
			Authorized:   stored.authorized,
			RequestTime:  stored.requestTime,
			ResponseTime: stored.responseTime,
			Vary:         vary,
			DialHost:     stored.dialHost,
		}

		responses = append(responses, response)
	}

	return responses, len(responses) > 0
}

// variant returns the stored response that response describes, with the
// fields that derive computes for a cache in the given mode, marked invalid so
// that it is validated before use. It reports false if the saved Vary fields
// don't match its Vary header.
func (response snapshotResponse) variant(shared bool) (*variant, bool) {
	header := response.Header
	if header == nil {
		header = make(http.Header)
	}

	names, star := parseVary(header)
	if star || len(names) != len(response.Vary) {
		return nil, false
	}

	vary := make([]varyField, len(response.Vary))

	for pos, field := range response.Vary {
		if field.Name != names[pos] {
			return nil, false
		}

		vary[pos] = varyField{name: field.Name, value: field.Value, present: field.Present}
	}

	sel := selection{vary: vary, varyStar: false, dialHost: response.DialHost}

	// Every stored header has a valid Date, but a damaged snapshot might not,
	// and derive replaces it.
	return &variant{
		derived:      derive(header, response.Status, response.RequestTime, response.ResponseTime, shared),
		selection:    sel,
		authorized:   response.Authorized,
		status:       response.Status,
		statusText:   response.StatusText,
		header:       header,
		body:         response.Body,
		decoded:      response.Decoded,
		invalid:      true,
		withdrawn:    false,
		requestTime:  response.RequestTime,
		responseTime: response.ResponseTime,
	}, true
}
