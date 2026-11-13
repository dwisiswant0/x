package cache

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// entityTag is a parsed ETag (RFC 9110 §8.8.3).
type entityTag struct {
	opaque string // including the quotes
	weak   bool
}

// parseETag parses an entity-tag: an optional "W/" and a quoted string of
// etagc characters.
func parseETag(field string) (entityTag, bool) {
	weak := strings.HasPrefix(field, "W/")
	if weak {
		field = field[2:]
	}

	if len(field) < 2 || field[0] != '"' || field[len(field)-1] != '"' {
		return entityTag{opaque: "", weak: false}, false
	}

	for pos := 1; pos < len(field)-1; pos++ {
		if char := field[pos]; char != 0x21 && (char < 0x23 || char == 0x7f) {
			return entityTag{opaque: "", weak: false}, false
		}
	}

	return entityTag{opaque: field, weak: weak}, true
}

// hasConditional reports whether req carries a precondition this cache can
// evaluate. Requests with other preconditions bypass the cache.
func hasConditional(req *http.Request) bool {
	return len(req.Header["If-None-Match"]) > 0 || len(req.Header["If-Modified-Since"]) > 0
}

// withValidators returns a copy of req that asks the origin to validate a
// stored response (RFC 9111 §4.3.1): If-None-Match with its entity tag, and
// If-Modified-Since with its Last-Modified value.
func withValidators(req *http.Request, stored *variant) *http.Request {
	out := req.Clone(req.Context())
	if out.Header == nil {
		out.Header = make(http.Header)
	}

	if stored.hasETag {
		out.Header.Set("If-None-Match", stored.header.Get("ETag"))
	}

	if stored.hasLM {
		out.Header.Set("If-Modified-Since", stored.header.Get("Last-Modified"))
	}

	return out
}

// notModified reports whether a precondition in req evaluates to false
// against a stored response, so the cache answers 304 (RFC 9111 §4.3.2).
//
// Only a stored 200 is evaluated: for any other status the origin would
// ignore the preconditions (RFC 9110 §13.2.1). If-None-Match takes precedence
// over If-Modified-Since (RFC 9110 §13.2.2).
func notModified(req *http.Request, stored *variant) bool {
	if stored.status != http.StatusOK {
		return false
	}

	if lines := req.Header["If-None-Match"]; len(lines) > 0 {
		// Without an ETag, the stored response has the zero tag, which only
		// "*" matches.
		return matchesAny(lines, stored.etag)
	}

	// RFC 9110 §13.1.3 ignores an invalid or list-valued If-Modified-Since.
	lines := req.Header["If-Modified-Since"]
	if len(lines) != 1 {
		return false
	}

	since, valid := parseHTTPDate(lines[0])
	if !valid {
		return false
	}

	modified := stored.lastModified
	if !stored.hasLM {
		// RFC 9111 §4.3.2: use Date, which derive sets to the receive time
		// if the response had none.
		modified = stored.date
	}

	return !modified.After(since)
}

// matchesAny reports whether an If-None-Match value lists "*" or an entity
// tag that matches tag by weak comparison (RFC 9110 §13.1.2). Malformed
// members never match.
func matchesAny(lines []string, tag entityTag) bool {
	for _, line := range lines {
		rest := line

		for {
			rest = strings.TrimLeft(rest, " \t,")
			if rest == "" {
				break
			}

			if rest[0] == '*' {
				return true
			}

			rest = strings.TrimPrefix(rest, "W/")
			if strings.HasPrefix(rest, `"`) {
				if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
					if rest[:end+2] == tag.opaque {
						return true
					}

					rest = rest[end+2:]

					continue
				}
			}

			// Skip a malformed member.
			_, rest, _ = strings.Cut(rest, ",")
		}
	}

	return false
}

// validators are the validator fields of a response (RFC 9110 §8.8).
type validators struct {
	etag         entityTag
	hasETag      bool
	lastModified time.Time
	hasLM        bool
	strongLM     bool
}

// validatorsOf returns the validators in header. Its Last-Modified is strong
// only if its Date is at least a second later (RFC 9110 §8.8.2.2).
func validatorsOf(header http.Header) validators {
	etag, hasETag := parseETag(header.Get("ETag"))
	lastModified, hasLM := singleDate(header, "Last-Modified")
	date, _ := singleDate(header, "Date")

	return validators{
		etag:         etag,
		hasETag:      hasETag,
		lastModified: lastModified,
		hasLM:        hasLM,
		strongLM:     hasLM && isStrongLM(date, lastModified),
	}
}

func (val validators) hasValidator() bool {
	return val.hasETag || val.hasLM
}

func (val validators) strong() bool {
	return val.hasETag && !val.etag.weak || val.strongLM
}

// matchStrong reports whether a stored response has one of these strong
// validators.
func (val validators) matchStrong(stored *variant) bool {
	return val.hasETag && !val.etag.weak && stored.hasETag && !stored.etag.weak && stored.etag.opaque == val.etag.opaque ||
		val.strongLM && stored.strongLM && stored.lastModified.Equal(val.lastModified)
}

// matchWeak reports whether a stored response has one of these validators,
// by weak comparison.
func (val validators) matchWeak(stored *variant) bool {
	return val.hasETag && stored.hasETag && stored.etag.opaque == val.etag.opaque ||
		val.hasLM && stored.hasLM && stored.lastModified.Equal(val.lastModified)
}

// sameAs reports whether val and other have the same ETag and Last-Modified.
func (val validators) sameAs(other validators) bool {
	return val.hasETag == other.hasETag && val.etag == other.etag &&
		val.hasLM == other.hasLM && val.lastModified.Equal(other.lastModified)
}

// identify returns the indexes of the stored responses that a 304 response
// to req updates (RFC 9111 §4.3.4). It starts from the responses that could
// have been chosen for req, fresh or not, and keeps:
//
//   - with strong validators in the 304, each response that has one of them,
//     and none if no response has one;
//   - with only weak validators, the most recent response that matches one;
//   - with no validators, the responses with the validators of sent, the
//     response that the cache's own conditional request validated, or if
//     sent is nil, a lone response that has no validators either.
//
// RFC 9110 §15.4.5 requires a 304 to carry the ETag that a 200 would, but
// some servers omit it. A 304 to the cache's conditional request still means
// the validators that request carried are current (RFC 9110 §13.1.2,
// §13.1.3), and §4.3.4 only forbids an update when the 304's strong
// validators match no stored response.
func (e *entry) identify(req *http.Request, header http.Header, sent *variant) []int {
	received := validatorsOf(header)
	initial := e.matching(req)

	switch {
	case received.strong():
		return e.filter(initial, received.matchStrong)
	case received.hasValidator():
		return e.mostRecent(e.filter(initial, received.matchWeak))
	case sent != nil:
		return e.filter(initial, func(stored *variant) bool { return stored.sameAs(sent.validators) })
	case len(initial) == 1 && !e.variants[initial[0]].hasValidator():
		return initial
	}

	return nil
}

// matching returns the indexes of the variants that could have been chosen
// for req.
func (e *entry) matching(req *http.Request) []int {
	var ids []int

	dial := dialHost(req)

	for pos, stored := range e.variants {
		if stored.matches(req, dial) {
			ids = append(ids, pos)
		}
	}

	return ids
}

// filter returns the indexes in ids whose variants keep reports true for.
func (e *entry) filter(ids []int, keep func(*variant) bool) []int {
	var kept []int

	for _, pos := range ids {
		if keep(e.variants[pos]) {
			kept = append(kept, pos)
		}
	}

	return kept
}

// mostRecent returns the index in ids of the most recent variant, or nil if
// ids is empty.
func (e *entry) mostRecent(ids []int) []int {
	if len(ids) == 0 {
		return nil
	}

	best := ids[0]

	for _, pos := range ids[1:] {
		if newer(e.variants[pos], e.variants[best]) {
			best = pos
		}
	}

	return []int{best}
}

// describedBy reports whether a 200 response to a HEAD request describes the
// same representation as v (RFC 9111 §4.3.5): each validator field it carries
// matches v's, and so does its Content-Length if it has one. A stored
// response without a Content-Length can't be compared, so it doesn't match.
func (v *variant) describedBy(header http.Header) bool {
	etag, lastModified := header.Get("ETag"), header.Get("Last-Modified")
	if etag != "" && etag != v.header.Get("ETag") ||
		lastModified != "" && lastModified != v.header.Get("Last-Modified") {
		return false
	}

	if length := header.Get("Content-Length"); length != "" {
		received, err := strconv.ParseInt(length, 10, 64)

		return err == nil && v.length >= 0 && received == v.length
	}

	return true
}
