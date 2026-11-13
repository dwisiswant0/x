package cache

import (
	"math"
	"strings"
	"time"
)

// directives holds the Cache-Control directives this package implements,
// from either a request (RFC 9111 §5.2.1) or a response (§5.2.2).
//
// The qualified forms of no-cache and private, which list field names, are
// treated as unqualified, which §5.2.2.4 and §5.2.2.7 permit.
type directives struct {
	maxAge   delta
	sMaxAge  delta
	maxStale delta
	minFresh delta

	noCache         bool
	noStore         bool
	onlyIfCached    bool
	mustRevalidate  bool
	proxyRevalidate bool
	mustUnderstand  bool
	public          bool
	private         bool
}

// delta is the argument of a directive that takes delta-seconds.
type delta struct {
	d   time.Duration
	set bool
}

// directive is one Cache-Control directive, as RFC 9111 §5.2 defines it:
//
//	cache-directive = token [ "=" ( token / quoted-string ) ]
type directive struct {
	name   string
	arg    string
	hasArg bool
}

// parseDirectives parses Cache-Control field lines (RFC 9111 §5.2). Names are
// case-insensitive, arguments may be tokens or quoted strings, and unknown
// directives are ignored (§5.2.3).
//
// When a directive repeats, the first occurrence wins (§4.2.1). An invalid
// delta-seconds argument reads as 0, so an invalid max-age makes a response
// stale, which §4.2.1 encourages.
func parseDirectives(lines []string) directives {
	var parsed directives

	for _, line := range lines {
		for line != "" {
			var next directive

			next, line = nextDirective(line)
			parsed.set(next)
		}
	}

	return parsed
}

func (cc *directives) set(dir directive) {
	name := strings.ToLower(dir.name)
	if !cc.setDelta(name, dir) {
		cc.setFlag(name)
	}
}

// setDelta sets the directive named name if it takes delta-seconds, and
// reports whether it does.
func (cc *directives) setDelta(name string, dir directive) bool {
	switch name {
	case "max-age":
		assignDelta(&cc.maxAge, dir.arg)
	case "s-maxage":
		assignDelta(&cc.sMaxAge, dir.arg)
	case "min-fresh":
		assignDelta(&cc.minFresh, dir.arg)
	case "max-stale":
		if dir.hasArg {
			assignDelta(&cc.maxStale, dir.arg)
		} else if !cc.maxStale.set {
			// Without an argument, any staleness is acceptable (§5.2.1.2).
			cc.maxStale = delta{d: math.MaxInt64, set: true}
		}
	default:
		return false
	}

	return true
}

// setFlag sets the directive named name if it is one without an argument.
func (cc *directives) setFlag(name string) {
	switch name {
	case "no-cache":
		cc.noCache = true
	case "no-store":
		cc.noStore = true
	case "only-if-cached":
		cc.onlyIfCached = true
	case "must-revalidate":
		cc.mustRevalidate = true
	case "proxy-revalidate":
		cc.proxyRevalidate = true
	case "must-understand":
		cc.mustUnderstand = true
	case "public":
		cc.public = true
	case "private":
		cc.private = true
	}
}

func assignDelta(dst *delta, arg string) {
	if dst.set {
		return
	}

	seconds, _ := parseDeltaSeconds(arg)
	*dst = delta{d: seconds, set: true}
}

// nextDirective splits the first directive off a Cache-Control field value,
// and returns it and the rest of the value. It skips anything else up to the
// next comma, so a malformed directive can't hide the ones after it.
func nextDirective(field string) (directive, string) {
	field = strings.TrimLeft(field, " \t,")
	nameEnd := tokenLen(field)
	dir := directive{name: field[:nameEnd], arg: "", hasArg: false}
	field = field[nameEnd:]

	if strings.HasPrefix(field, "=") {
		dir.hasArg = true
		field = field[1:]

		if strings.HasPrefix(field, `"`) {
			dir.arg, field = quotedString(field)
		} else {
			argEnd := tokenLen(field)
			dir.arg, field = field[:argEnd], field[argEnd:]
		}
	}

	return dir, skipToComma(field)
}

// quotedString unescapes the quoted-string at the start of field, and returns
// it and the rest of field after it. An unterminated string runs to the end
// of field.
func quotedString(field string) (string, string) {
	var unescaped strings.Builder

	for pos := 1; pos < len(field); pos++ {
		switch char := field[pos]; char {
		case '"':
			return unescaped.String(), field[pos+1:]
		case '\\':
			if pos+1 < len(field) {
				pos++
				unescaped.WriteByte(field[pos])
			}
		default:
			unescaped.WriteByte(char)
		}
	}

	return unescaped.String(), ""
}

// skipToComma returns field from its first comma that isn't inside a quoted
// string, or "" if there is none.
func skipToComma(field string) string {
	for pos := 0; pos < len(field); pos++ {
		switch field[pos] {
		case ',':
			return field[pos:]
		case '"':
			_, rest := quotedString(field[pos:])
			if rest == "" {
				return ""
			}

			pos = len(field) - len(rest) - 1
		}
	}

	return ""
}

// tokenLen returns the length of the token (RFC 9110 §5.6.2) at the start of
// text.
func tokenLen(text string) int {
	for pos := range len(text) {
		if !isTokenChar(text[pos]) {
			return pos
		}
	}

	return len(text)
}

func isTokenChar(char byte) bool {
	switch {
	case 'a' <= char && char <= 'z', 'A' <= char && char <= 'Z', '0' <= char && char <= '9':
		return true
	}

	return strings.IndexByte("!#$%&'*+-.^_`|~", char) >= 0
}
