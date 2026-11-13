package cache

import (
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

// describe returns dirs as a canonical string: the delta-seconds directives
// that are set, as name=seconds, and then the flags that are set, in a fixed
// order and separated by spaces. A max-stale without an argument is just
// "max-stale".
func describe(dirs directives) string {
	var parts []string

	for _, arg := range []struct {
		name  string
		value delta
	}{
		{ccMaxAge, dirs.maxAge},
		{"s-maxage", dirs.sMaxAge},
		{ccMaxStale, dirs.maxStale},
		{"min-fresh", dirs.minFresh},
	} {
		switch {
		case !arg.value.set:
		case arg.value.d == math.MaxInt64:
			parts = append(parts, arg.name)
		default:
			parts = append(parts, arg.name+"="+strconv.FormatInt(int64(arg.value.d/time.Second), 10))
		}
	}

	for _, flag := range []struct {
		name string
		set  bool
	}{
		{ccNoCache, dirs.noCache},
		{ccNoStore, dirs.noStore},
		{"only-if-cached", dirs.onlyIfCached},
		{"must-revalidate", dirs.mustRevalidate},
		{"proxy-revalidate", dirs.proxyRevalidate},
		{"must-understand", dirs.mustUnderstand},
		{ccPublic, dirs.public},
		{ccPrivate, dirs.private},
	} {
		if flag.set {
			parts = append(parts, flag.name)
		}
	}

	return strings.Join(parts, " ")
}

func TestParseDirectives(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.2.3-ignore-unknown")

	for _, test := range []struct {
		lines []string
		want  string
	}{
		{nil, ""},
		{[]string{ccMaxAge60}, ccMaxAge60},
		{[]string{"MAX-AGE=60, No-Store"}, "max-age=60 no-store"},
		{[]string{`max-age="60"`}, ccMaxAge60},
		{[]string{"max-age=003600"}, "max-age=3600"},
		// The first occurrence wins, on one line or across lines.
		{[]string{"max-age=1800, max-age=1"}, "max-age=1800"},
		{[]string{ccMaxAge1, "max-age=1800"}, ccMaxAge1},
		// Invalid arguments read as 0.
		{[]string{"max-age=-1"}, ccMaxAge0},
		{[]string{"max-age='3600'"}, ccMaxAge0},
		{[]string{"max-age=3600.0"}, ccMaxAge0},
		{[]string{"max-age=3600a"}, ccMaxAge0},
		{[]string{ccMaxAge}, ccMaxAge0},
		{[]string{"max-age =3600"}, ccMaxAge0},
		{[]string{"max-age= 3600"}, ccMaxAge0},
		{[]string{"max-age=99999999999"}, "max-age=2147483648"},
		// Directives inside quoted strings aren't directives.
		{[]string{`extension="max-age=3600", max-age=1`}, ccMaxAge1},
		{[]string{`max-age=1, extension="max-age=3600"`}, ccMaxAge1},
		{[]string{`no-cache="a, b", private="c,d", max-age=5`}, "max-age=5 no-cache private"},
		{[]string{`x="unterminated, max-age=5`}, ""},
		{[]string{`x="a\"b", max-age=5`}, "max-age=5"},
		// Unknown directives and junk are skipped.
		{[]string{"immutable, stale-while-revalidate=60, foo bar, public"}, ccPublic},
		{[]string{",, ,s-maxage=10,,"}, "s-maxage=10"},
		{[]string{ccMaxStale}, ccMaxStale},
		{[]string{"max-stale=5, max-stale"}, "max-stale=5"},
		{[]string{"min-fresh=7"}, "min-fresh=7"},
		{
			[]string{"no-cache, no-store, only-if-cached, must-revalidate, proxy-revalidate, must-understand, public, private"},
			"no-cache no-store only-if-cached must-revalidate proxy-revalidate must-understand public private",
		},
	} {
		if got := describe(parseDirectives(test.lines)); got != test.want {
			t.Errorf("parseDirectives(%q) = %q, want %q", test.lines, got, test.want)
		}
	}
}

func FuzzParseDirectives(f *testing.F) {
	for _, text := range []string{
		"max-age=60, no-store",
		`no-cache="a, b", max-age="5"`,
		`x="a\"b`,
		"max-stale, min-fresh=1, s-maxage=99999999999999999999",
	} {
		f.Add(text, ccPublic)
	}

	f.Fuzz(func(t *testing.T, first, second string) {
		dirs := parseDirectives([]string{first, second})
		for _, d := range []delta{dirs.maxAge, dirs.sMaxAge, dirs.minFresh} {
			if d.d < 0 || d.d > maxDelta || !d.set && d.d != 0 {
				t.Fatalf("parseDirectives(%q, %q) = %+v: delta out of range", first, second, dirs)
			}
		}

		if dirs.maxStale.d < 0 {
			t.Fatalf("parseDirectives(%q, %q): negative max-stale", first, second)
		}
	})
}
