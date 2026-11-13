package cache

import (
	"net/http"
	"testing"
	"time"
)

func TestParseHTTPDate(t *testing.T) {
	t.Parallel()

	covers(t, "9110-5.6.7-accept-formats", "9111-4.2-case-insensitive", "9111-4.2-non-gmt")

	want := time.Date(1994, time.November, 6, 8, 49, 37, 0, time.UTC)

	for _, input := range []string{
		dateIMF,
		dateRFC850,
		dateANSIC,
		"Sun Nov 06 08:49:37 1994",
		"sun, 06 nov 1994 08:49:37 gmt",
		"SUN, 06 NOV 1994 08:49:37 GMT",
		"SUNDAY, 06-NOV-94 08:49:37 gmt",
		"SUN NOV  6 08:49:37 1994",
		// Recipients don't check that the day name matches the date.
		"Mon, 06 Nov 1994 08:49:37 GMT",
	} {
		got, ok := parseHTTPDate(input)
		if !ok || !got.Equal(want) {
			t.Errorf("parseHTTPDate(%q) = %v, %t; want %v", input, got, ok, want)
		}
	}

	// A leap second normalizes to the next minute.
	if got, ok := parseHTTPDate("Sat, 31 Dec 2016 23:59:60 GMT"); !ok ||
		!got.Equal(time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("leap second: got %v, %t", got, ok)
	}
}

func TestParseHTTPDateRejects(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.2-non-gmt")

	for _, input := range []string{
		"",
		"0",
		"-1",
		"Sun, 06 Nov 1994 08:49:37 UTC",
		"Sun, 06 Nov 1994 08:49:37 EST",
		"Thu, 18 Aug 2050 02:01:18 AEST",
		"Sun, 06 Nov 1994 08:49:37 +0000",
		"Sun, 06 Nov 94 08:49:37 GMT",
		"Sun 06 Nov 1994 08:49:37 GMT",
		"Thu, 18  Aug  2050 02:01:18 GMT",
		"Sun,  06 Nov 1994 08:49:37 GMT",
		" Sun, 06 Nov 1994 08:49:37 GMT",
		"Sun, 06 Nov 1994 08:49:37 GMT ",
		"Sun, 06-Nov-1994 08:49:37 GMT",
		"Sun, 06 Nov 1994 08.49.37 GMT",
		"Sun, 06 Nov 1994 8:49:37 GMT",
		"Thu, 18 Aug 2050 2:01:18 GMT",
		"Sun, 31 Nov 1994 08:49:37 GMT",
		"Sun, 00 Nov 1994 08:49:37 GMT",
		"Sun, 06 Nov 1994 24:00:00 GMT",
		"Sun, 06 Nov 1994 08:60:00 GMT",
		"Sun, 06 Foo 1994 08:49:37 GMT",
		"Xyz, 06 Nov 1994 08:49:37 GMT",
		"Sunday, 06-Nov-94 08:49:37 UTC",
		"Sun, 06-Nov-94 08:49:37 GMT",
		"Sunday, 06 Nov 1994 08:49:37 GMT",
		"Sun Nov  6 08:49:37 94  ",
		"Sun Nov 6 08:49:37 1994",
		"Sun Nov  6 08:49:37 1994 GMT",
		"Sun, +6 Nov 1994 08:49:37 GMT",
		"Fri, 31 Dec 9999 23:59:60 GMT",
	} {
		if got, ok := parseHTTPDate(input); ok {
			t.Errorf("parseHTTPDate(%q) = %v, want invalid", input, got)
		}
	}
}

func TestParseRFC850Year(t *testing.T) {
	t.Parallel()

	covers(t, "9110-5.6.7-rfc850-year")

	now := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		now  time.Time
		in   string
		year int
	}{
		// time.Parse would put years 69 to 99 in the 1900s.
		{now, "Thursday, 01-Jan-70 00:00:00 GMT", 2070},
		{now, "Friday, 13-Nov-76 00:00:00 GMT", 2076},
		{now, "Monday, 16-Nov-76 00:00:00 GMT", 1976},
		{now, "Friday, 01-Jan-99 00:00:00 GMT", 1999},
		{now, "Saturday, 01-Jan-00 00:00:00 GMT", 2000},
		{now, dateRFC850, 1994},
		{now, "Thursday, 18-Aug-50 02:01:18 GMT", 2050},
		{time.Date(2090, time.January, 1, 0, 0, 0, 0, time.UTC), "Monday, 01-Jan-10 00:00:00 GMT", 2110},
	} {
		got, ok := parseRFC850(test.in, test.now)
		if !ok || got.Year() != test.year {
			t.Errorf("parseRFC850(%q) at %d = %v, %t; want year %d", test.in, test.now.Year(), got, ok, test.year)
		}
	}
}

// TestParseHTTPDateIgnoresLocalZone doesn't run in parallel, because it
// replaces time.Local, and it uses time.Local on purpose.
//
//nolint:paralleltest,gosmopolitan // it mutates and reads time.Local
func TestParseHTTPDateIgnoresLocalZone(t *testing.T) {
	covers(t, "9111-4.2-local-tz")

	local := time.Local

	t.Cleanup(func() { time.Local = local })
	// http.ParseTime's RFC 850 layout would read the zone in this location.
	time.Local = time.FixedZone("GMT", 5*60*60)

	want := time.Date(1994, time.November, 6, 8, 49, 37, 0, time.UTC)
	for _, input := range []string{
		dateIMF,
		dateRFC850,
		dateANSIC,
	} {
		if got, ok := parseHTTPDate(input); !ok || !got.Equal(want) {
			t.Errorf("parseHTTPDate(%q) = %v, %t; want %v", input, got, ok, want)
		}
	}

	if got := formatHTTPDate(want.In(time.Local)); got != dateIMF {
		t.Errorf("formatHTTPDate = %q", got)
	}
}

func FuzzParseHTTPDate(f *testing.F) {
	for _, input := range []string{
		dateIMF,
		dateRFC850,
		dateANSIC,
		"sat, 31 dec 2016 23:59:60 gmt",
		"Wed, 29 Feb 2000 00:00:00 GMT",
		"Thu, 18 Aug 2050 2:01:18 GMT",
		"Fri, 31 Dec 9999 23:59:60 GMT",
	} {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input string) {
		parsed, valid := parseHTTPDate(input)
		if !valid {
			return
		}

		// Every parsed date has an IMF-fixdate form that parses back to it.
		imf := formatHTTPDate(parsed)
		if len(imf) != len(http.TimeFormat) {
			t.Fatalf("formatHTTPDate(%v) = %q", parsed, imf)
		}

		again, valid := parseHTTPDate(imf)
		if !valid || !again.Equal(parsed) {
			t.Fatalf("%q parsed as %v, but its IMF-fixdate %q parsed as %v, %t", input, parsed, imf, again, valid)
		}
	})
}
