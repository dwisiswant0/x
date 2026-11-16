package cache

import (
	"net/http"
	"strings"
	"time"
)

const (
	// maxDeltaSeconds is 2^31. RFC 9111 §1.2.2 requires delta-seconds values
	// and calculations that overflow to be treated as 2^31 seconds.
	maxDeltaSeconds = 2147483648

	// maxDelta is the largest age or lifetime the cache represents.
	maxDelta = maxDeltaSeconds * time.Second

	// heuristicFraction divides the time since Last-Modified to give the
	// heuristic freshness lifetime: 10 gives the 10% that §4.2.2 suggests.
	heuristicFraction = 10
)

// parseDeltaSeconds parses delta-seconds (RFC 9111 §1.2.2), which is one or
// more ASCII digits. Values above 2^31 saturate.
func parseDeltaSeconds(digits string) (time.Duration, bool) {
	if digits == "" {
		return 0, false
	}

	var seconds int64

	for pos := range len(digits) {
		char := digits[pos]
		if char < '0' || char > '9' {
			return 0, false
		}

		if seconds <= maxDeltaSeconds {
			seconds = seconds*decimalBase + int64(char-'0')
		}
	}

	return time.Duration(min(seconds, maxDeltaSeconds)) * time.Second, true
}

// parseAge returns the age_value of a response (RFC 9111 §5.1). Of a
// list-valued Age, only the first member counts, and an invalid Age is
// ignored.
func parseAge(header http.Header) time.Duration {
	lines := header.Values("Age")
	if len(lines) == 0 {
		return 0
	}

	first, _, _ := strings.Cut(lines[0], ",")
	age, _ := parseDeltaSeconds(strings.Trim(first, " \t"))

	return age
}

// freshnessLifetime returns the freshness lifetime of a response, using the
// first rule of RFC 9111 §4.2.1 that applies: s-maxage in a shared cache,
// max-age, Expires minus Date, and then a heuristic (§4.2.2).
func freshnessLifetime(header http.Header, status int, dirs directives, date time.Time, shared bool) time.Duration {
	switch {
	case shared && dirs.sMaxAge.set:
		return dirs.sMaxAge.d
	case dirs.maxAge.set:
		return dirs.maxAge.d
	case len(header.Values("Expires")) > 0:
		// An invalid Expires, such as "0", means already expired (§5.3).
		expires, valid := singleDate(header, "Expires")
		if !valid {
			return 0
		}

		return clampDelta(expires.Sub(date))
	}

	return heuristicLifetime(header, status, dirs, date, shared)
}

// heuristicLifetime returns the heuristic freshness lifetime of a response
// without explicit expiration (§4.2.2), if heuristicAllowed allows one.
func heuristicLifetime(header http.Header, status int, dirs directives, date time.Time, shared bool) time.Duration {
	if !heuristicAllowed(status, dirs, shared) {
		return 0
	}

	lastModified, valid := singleDate(header, "Last-Modified")
	if !valid || lastModified.After(date) {
		return 0
	}

	return clampDelta(date.Sub(lastModified) / heuristicFraction)
}

// heuristicAllowed reports whether a response may have a heuristic freshness
// lifetime: one with a heuristically cacheable status, or a directive that
// marks it cacheable (RFC 9111 §3, §5.2.2.7).
func heuristicAllowed(status int, dirs directives, shared bool) bool {
	return heuristicallyCacheable(status) || dirs.public || dirs.private && !shared
}

// heuristicallyCacheable reports whether RFC 9110 §15.1 defines the status as
// heuristically cacheable. It omits 206, which this cache never stores.
func heuristicallyCacheable(status int) bool {
	switch status {
	case http.StatusOK, http.StatusNonAuthoritativeInfo, http.StatusNoContent,
		http.StatusMultipleChoices, http.StatusMovedPermanently, http.StatusPermanentRedirect,
		http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone,
		http.StatusRequestURITooLong, http.StatusNotImplemented:
		return true
	}

	return false
}

// singleDate parses a field that holds one HTTP-date. A field with several
// lines is invalid.
func singleDate(header http.Header, name string) (time.Time, bool) {
	lines := header.Values(name)
	if len(lines) != 1 {
		return time.Time{}, false
	}

	return parseHTTPDate(lines[0])
}

func clampDelta(d time.Duration) time.Duration {
	return min(max(d, 0), maxDelta)
}
