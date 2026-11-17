package cache

import (
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// variantLimits bounds the responses stored for one target URI, so a resource
// that varies on a high-cardinality field can't grow its entry without bound.
// perServer applies to the responses from one server (see dialHost), and total
// to all of them, so a proxy that spreads one Host over several backends keeps
// their responses side by side instead of evicting each other.
type variantLimits struct {
	perServer int
	total     int
}

// serversPerTarget is how many servers' worth of responses a target URI holds
// in all.
const serversPerTarget = 8

// newVariantLimits returns the limits for perServer responses from one server.
func newVariantLimits(perServer int) variantLimits {
	total := math.MaxInt
	if perServer <= math.MaxInt/serversPerTarget {
		total = perServer * serversPerTarget
	}

	return variantLimits{perServer: perServer, total: total}
}

// entry holds the stored responses for one target URI.
//
// Entries and variants are never modified once stored. Every update builds
// new values, so a reader always sees consistent values without locking.
type entry struct {
	variants []*variant
}

// weigh returns the size of ent for [WithMaxBytes], the sum of the sizes of
// its responses.
func weigh(_ string, ent *entry) int {
	size := 0
	for _, stored := range ent.variants {
		size += stored.size()
	}

	return size
}

// variant is one stored response to a GET request.
type variant struct {
	derived
	selection

	// authorized reports that a request this response answered had an
	// Authorization field, which limits storing it in a shared cache (RFC
	// 9111 §3.5).
	authorized bool

	status     int
	statusText string
	header     http.Header
	body       []byte

	// decoded reports that the next RoundTripper, such as Go's http.Transport,
	// removed the content coding from the body, and with it the
	// Content-Encoding and Content-Length fields.
	decoded bool

	// invalid marks a response that must be validated before reuse: after an
	// unsafe request (RFC 9111 §4.4), a mismatched HEAD (§4.3.5), an update
	// that couldn't be stored, or Load.
	invalid bool

	// withdrawn marks a response whose last update couldn't be stored, for
	// example because it added no-store (see Transport.updateVariant). Its
	// stored fields may no longer apply, so Save doesn't write it.
	withdrawn bool

	requestTime  time.Time
	responseTime time.Time
}

// selection holds what the request that produced a stored response
// contributes to choosing it for later requests: the fields its Vary
// nominates (RFC 9111 §4.1), and the server it was sent to.
type selection struct {
	vary []varyField // sorted by name

	// varyStar is never set in a stored response, since worthStoring rejects
	// it, but matches checks it anyway: RFC 9111 §4.1 states the rule there.
	varyStar bool

	dialHost string // see dialHost
}

// derived holds what the cache computes from a stored response's header and
// the times of the exchange that produced it.
type derived struct {
	validators

	cc         directives
	date       time.Time
	initialAge time.Duration // corrected_initial_age (§4.2.3)
	lifetime   time.Duration // freshness_lifetime (§4.2.1)
	length     int64         // the received Content-Length, or -1
	headerSize int           // the bytes of the header's names and values
}

// varyField is a request field that a stored response's Vary nominates, with
// the value it had in the request that produced the response.
type varyField struct {
	name    string
	value   string
	present bool
}

// newVariant records a response to req for storage. The body is added
// later, once it has been read.
func newVariant(req *http.Request, trip exchange, shared bool) *variant {
	header := storedHeader(trip.res.Header)
	code := trip.res.StatusCode

	statusText := trip.res.Status
	if statusText == "" {
		statusText = strconv.Itoa(code) + " " + http.StatusText(code)
	}

	return &variant{
		derived:      derive(header, code, trip.requestTime, trip.responseTime, shared),
		selection:    selectionFor(req, header),
		authorized:   hasAuthorization(req),
		status:       code,
		statusText:   statusText,
		header:       header,
		body:         nil,
		decoded:      trip.res.Uncompressed,
		invalid:      false,
		withdrawn:    false,
		requestTime:  trip.requestTime,
		responseTime: trip.responseTime,
	}
}

// updated returns a copy of v that a 304 or HEAD response to req has
// validated, with its header updated (RFC 9111 §3.2).
func (v *variant) updated(req *http.Request, trip exchange, shared bool) *variant {
	header := updatedHeader(v.header, trip.res.Header, v.decoded)

	return &variant{
		derived:      derive(header, v.status, trip.requestTime, trip.responseTime, shared),
		selection:    selectionFor(req, header),
		authorized:   v.authorized || hasAuthorization(req),
		status:       v.status,
		statusText:   v.statusText,
		header:       header,
		body:         v.body,
		decoded:      v.decoded,
		invalid:      false,
		withdrawn:    false,
		requestTime:  trip.requestTime,
		responseTime: trip.responseTime,
	}
}

// replaceInvalidDate sets the Date of a header for storage to the time the
// response was received if its Date is invalid, which RFC 9110 §6.6.1 allows.
func replaceInvalidDate(header http.Header, received time.Time) {
	if _, valid := singleDate(header, "Date"); !valid {
		header.Set("Date", formatHTTPDate(received))
	}
}

func (v *variant) invalidated() *variant {
	copied := *v
	copied.invalid = true

	return &copied
}

// selectionFor returns the selection of a response with the given header to
// req.
func selectionFor(req *http.Request, header http.Header) selection {
	names, star := parseVary(header)

	return selection{vary: nominate(names, req.Header), varyStar: star, dialHost: dialHost(req)}
}

func hasAuthorization(req *http.Request) bool {
	return len(req.Header.Values("Authorization")) > 0
}

// derive computes the derived fields of a response with the given header and
// status, received at responseTime for a request sent at requestTime, for
// storage. It first replaces an invalid Date in header with responseTime,
// which RFC 9110 §6.6.1 allows, so the header always agrees with the result.
func derive(header http.Header, status int, requestTime, responseTime time.Time, shared bool) derived {
	replaceInvalidDate(header, responseTime)

	dirs := parseDirectives(header.Values("Cache-Control"))
	date, _ := singleDate(header, "Date")

	// RFC 9111 §4.2.3.
	apparentAge := max(responseTime.Sub(date), 0)
	correctedAge := parseAge(header) + responseTime.Sub(requestTime)

	return derived{
		validators: validatorsOf(header),
		cc:         dirs,
		date:       date,
		initialAge: clampDelta(max(apparentAge, correctedAge)),
		lifetime:   freshnessLifetime(header, status, dirs, date, shared),
		length:     contentLength(header),
		headerSize: headerSize(header),
	}
}

// contentLength returns the Content-Length of a header, or -1 if it has no
// valid one.
func contentLength(header http.Header) int64 {
	field := header.Get("Content-Length")
	if field == "" {
		// ParseInt would allocate an error to say so.
		return -1
	}

	length, err := strconv.ParseInt(field, 10, 64)
	if err != nil || length < 0 {
		return -1
	}

	return length
}

// size returns the size of v for [WithMaxBytes]: the bytes of its body, its
// header fields, and the request fields that its Vary header names.
func (v *variant) size() int {
	size := len(v.body) + v.headerSize
	for _, field := range v.vary {
		size += len(field.name) + len(field.value)
	}

	return size
}

// headerSize returns the bytes of the names and values in header.
func headerSize(header http.Header) int {
	size := 0

	for name, values := range header {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}

	return size
}

func (v *variant) currentAge(now time.Time) time.Duration {
	return clampDelta(v.initialAge + max(now.Sub(v.responseTime), 0))
}

// isStrongLM reports whether a Last-Modified value is a strong validator,
// which RFC 9110 §8.8.2.2 deduces when Date is at least a second later.
func isStrongLM(date, lastModified time.Time) bool {
	return !date.Before(lastModified.Add(time.Second))
}

// parseVary returns the field names a Vary header nominates, canonicalized,
// sorted, and without duplicates, and whether it has a "*" member.
func parseVary(header http.Header) ([]string, bool) {
	var names []string

	star := false

	for _, line := range header.Values("Vary") {
		for name := range strings.SplitSeq(line, ",") {
			switch name = strings.Trim(name, " \t"); name {
			case "":
			case "*":
				star = true
			default:
				names = append(names, http.CanonicalHeaderKey(name))
			}
		}
	}

	slices.Sort(names)

	return slices.Compact(names), star
}

func nominate(names []string, header http.Header) []varyField {
	if len(names) == 0 {
		return nil
	}

	fields := make([]varyField, len(names))

	for pos, name := range names {
		lines := header.Values(name)
		fields[pos] = varyField{name: name, value: joinLines(lines), present: len(lines) > 0}
	}

	return fields
}

// matches reports whether the request fields nominated by v's Vary match the
// ones in req (RFC 9111 §4.1). A "*" never matches, and an absent field
// matches only an absent field. req must also be sent to the same server:
// dial is req's dialHost, which a caller comparing req with several stored
// responses computes once.
func (v *variant) matches(req *http.Request, dial string) bool {
	if v.varyStar || v.dialHost != dial {
		return false
	}

	for _, field := range v.vary {
		lines := req.Header[field.name] // canonical, see parseVary
		if (len(lines) > 0) != field.present || joinLines(lines) != field.value {
			return false
		}
	}

	return true
}

// joinLines combines field lines into one value (RFC 9110 §5.3).
//
// It doesn't normalize the value further. Lowercasing or reordering list
// members could make requests that need different responses match; strict
// matching can only cost a cache hit.
func joinLines(lines []string) string {
	switch len(lines) {
	case 0:
		return ""
	case 1:
		return strings.Trim(lines[0], " \t")
	}

	trimmed := make([]string, len(lines))

	for pos, line := range lines {
		trimmed[pos] = strings.Trim(line, " \t")
	}

	return strings.Join(trimmed, ", ")
}

// choose returns the stored response to use for req, or nil if none matches
// its Vary fields (RFC 9111 §4.1).
func (e *entry) choose(req *http.Request) *variant {
	var best *variant

	dial := dialHost(req)

	for _, stored := range e.variants {
		if stored.matches(req, dial) && (best == nil || preferred(stored, best)) {
			best = stored
		}
	}

	return best
}

// preferred reports whether a is a better choice than b among responses that
// match a request. RFC 9111 §4.1 prefers a response with a Vary field, and
// §4 then prefers the most recent.
func preferred(a, b *variant) bool {
	if hasVaryA, hasVaryB := len(a.vary) > 0, len(b.vary) > 0; hasVaryA != hasVaryB {
		return hasVaryA
	}

	return newer(a, b)
}

// newer reports whether a is more recent than b by Date, with ties broken by
// the time each was received.
func newer(a, b *variant) bool {
	if !a.date.Equal(b.date) {
		return a.date.After(b.date)
	}

	return a.responseTime.After(b.responseTime)
}

// withVariant returns old with added in it, and how many responses it
// dropped. added replaces a response with the same Vary fields from the same
// server. Past limits.perServer responses from added's server, the oldest of
// them is dropped, and past limits.total in all, the oldest response is.
func withVariant(old []*variant, added *variant, limits variantLimits) ([]*variant, int) {
	variants := make([]*variant, 0, len(old)+1)
	sameServer := 1

	for _, stored := range old {
		switch {
		case stored.sameSelection(added):
		case stored.dialHost == added.dialHost:
			variants = append(variants, stored)
			sameServer++
		default:
			variants = append(variants, stored)
		}
	}

	variants = append(variants, added)
	dropped := 0

	if sameServer > limits.perServer {
		variants = dropOldest(variants, func(stored *variant) bool { return stored.dialHost == added.dialHost })
		dropped++
	}

	if len(variants) > limits.total {
		variants = dropOldest(variants, func(*variant) bool { return true })
		dropped++
	}

	return variants, dropped
}

// fitBytes returns variants without the responses larger than limit and then
// without the oldest, until their sizes add up to at most limit, so that the
// cache can store them together. It doesn't modify variants.
func fitBytes(variants []*variant, limit int) []*variant {
	size := 0
	for _, stored := range variants {
		size += stored.size()
	}

	if size <= limit {
		return variants
	}

	kept := make([]*variant, 0, len(variants))
	size = 0

	for _, stored := range variants {
		if stored.size() <= limit {
			kept = append(kept, stored)
			size += stored.size()
		}
	}

	for size > limit {
		pos := oldest(kept, func(*variant) bool { return true })
		size -= kept[pos].size()
		kept = slices.Delete(kept, pos, pos+1)
	}

	return kept
}

// sameSelection reports whether other answers the same requests as v.
func (v *variant) sameSelection(other *variant) bool {
	return other.dialHost == v.dialHost && slices.Equal(other.vary, v.vary)
}

// dropOldest removes the oldest of the variants for which candidate reports
// true. At least one must.
func dropOldest(variants []*variant, candidate func(*variant) bool) []*variant {
	pos := oldest(variants, candidate)

	return slices.Delete(variants, pos, pos+1)
}

// oldest returns the position of the oldest of the variants for which
// candidate reports true, or -1 if there is none.
func oldest(variants []*variant, candidate func(*variant) bool) int {
	found := -1

	for pos, stored := range variants {
		if candidate(stored) && (found < 0 || newer(variants[found], stored)) {
			found = pos
		}
	}

	return found
}
