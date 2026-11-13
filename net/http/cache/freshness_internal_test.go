package cache

import (
	"net/http"
	"testing"
	"time"
)

func TestParseDeltaSeconds(t *testing.T) {
	t.Parallel()

	covers(t, "9111-1.2.2-overflow")

	for _, test := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"0", 0, true},
		{"60", time.Minute, true},
		{"007", 7 * time.Second, true},
		{"2147483647", maxDelta - time.Second, true},
		{"2147483648", maxDelta, true},
		{"2147483649", maxDelta, true},
		{"99999999999999999999999999", maxDelta, true},
		{"", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"1.5", 0, false},
		{" 1", 0, false},
	} {
		got, ok := parseDeltaSeconds(test.in)
		if got != test.want || ok != test.ok {
			t.Errorf("parseDeltaSeconds(%q) = %v, %t; want %v, %t", test.in, got, ok, test.want, test.ok)
		}
	}
}

func TestParseAge(t *testing.T) {
	t.Parallel()

	covers(t, "9111-5.1-age-list", "9111-5.1-age-invalid")

	for _, test := range []struct {
		lines []string
		want  time.Duration
	}{
		{nil, 0},
		{[]string{"30"}, 30 * time.Second},
		{[]string{"30, 0"}, 30 * time.Second},
		{[]string{"0, 30"}, 0},
		{[]string{"30", "0"}, 30 * time.Second},
		{[]string{"0", "30"}, 0},
		{[]string{"old"}, 0},
		{[]string{"-5"}, 0},
		{[]string{"1.5"}, 0},
		{[]string{""}, 0},
		{[]string{"2147483649"}, maxDelta},
	} {
		h := http.Header{hdrAge: test.lines}
		if got := parseAge(h); got != test.want {
			t.Errorf("parseAge(%q) = %v, want %v", test.lines, got, test.want)
		}
	}
}

// freshnessCase is a response, and the freshness lifetime a cache computes
// for it. The Date of the response is date.
type freshnessCase struct {
	name   string
	status int
	header http.Header
	shared bool
	want   time.Duration
}

func freshnessCases(date time.Time) []freshnessCase {
	httpDate := func(d time.Duration) string { return formatHTTPDate(date.Add(d)) }

	return []freshnessCase{
		{ccMaxAge, 200, http.Header{hdrCacheControl: {ccMaxAge60}}, false, time.Minute},
		{
			"s-maxage ignored by private cache", 200,
			http.Header{hdrCacheControl: {"s-maxage=10, max-age=60"}}, false, time.Minute,
		},
		{
			"s-maxage first in shared cache", 200,
			http.Header{hdrCacheControl: {"max-age=60, s-maxage=10"}}, true, 10 * time.Second,
		},
		{
			"max-age over Expires", 200,
			http.Header{hdrCacheControl: {ccMaxAge0}, hdrExpires: {httpDate(time.Hour)}}, false, 0,
		},
		{
			"s-maxage over Expires", 200,
			http.Header{hdrCacheControl: {"s-maxage=5"}, hdrExpires: {httpDate(time.Hour)}}, true, 5 * time.Second,
		},
		{"Expires minus Date", 200, http.Header{hdrExpires: {httpDate(time.Hour)}}, false, time.Hour},
		{"Expires before Date", 200, http.Header{hdrExpires: {httpDate(-time.Hour)}}, false, 0},
		{"invalid Expires", 200, http.Header{hdrExpires: {"0"}}, false, 0},
		{"Expires on two lines", 200, http.Header{hdrExpires: {httpDate(time.Hour), httpDate(time.Hour)}}, false, 0},
		{
			"invalid Expires blocks heuristics", 200,
			http.Header{hdrExpires: {"0"}, hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 0,
		},
		{
			"max-age=0 blocks heuristics", 200,
			http.Header{hdrCacheControl: {ccMaxAge0}, hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 0,
		},
		{"heuristic", 200, http.Header{hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 10 * time.Hour},
		{"heuristic 404", 404, http.Header{hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 10 * time.Hour},
		{"no heuristic for 201", 201, http.Header{hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 0},
		{
			"heuristic for public 201", 201,
			http.Header{hdrCacheControl: {ccPublic}, hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 10 * time.Hour,
		},
		{
			"heuristic for private in private cache", 599,
			http.Header{hdrCacheControl: {ccPrivate}, hdrLastModified: {httpDate(-100 * time.Hour)}}, false, 10 * time.Hour,
		},
		{
			"no heuristic for private in shared cache", 599,
			http.Header{hdrCacheControl: {ccPrivate}, hdrLastModified: {httpDate(-100 * time.Hour)}}, true, 0,
		},
		{"no heuristic without Last-Modified", 200, http.Header{}, false, 0},
		{"no heuristic for future Last-Modified", 200, http.Header{hdrLastModified: {httpDate(time.Hour)}}, false, 0},
		{"Expires far away", 200, http.Header{hdrExpires: {"Fri, 31 Dec 9999 23:59:59 GMT"}}, false, maxDelta},
	}
}

func TestFreshnessLifetime(t *testing.T) {
	t.Parallel()

	covers(t,
		"9111-4.2.1-lifetime",
		"9111-4.2.2-heuristic",
		"9111-4.2.2-no-explicit",
		"9111-5.3-invalid-date",
		"9111-5.3-ignore-max-age",
		"9111-5.3-ignore-s-maxage",
	)

	date := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, test := range freshnessCases(date) {
		cc := parseDirectives(test.header.Values(hdrCacheControl))
		if got := freshnessLifetime(test.header, test.status, cc, date, test.shared); got != test.want {
			t.Errorf("%s: freshnessLifetime = %v, want %v", test.name, got, test.want)
		}
	}
}
