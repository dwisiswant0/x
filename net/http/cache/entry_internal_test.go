package cache

import (
	"math"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"
)

// testTime returns the time the stored test responses are received at.
func testTime() time.Time {
	return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
}

// testVariant returns a stored response to a GET request with the request
// fields reqFields, received at testTime plus offset, with the given status
// and response fields.
func testVariant(status int, offset time.Duration, reqFields []string, resFields ...string) *variant {
	header := make(http.Header)
	for name, value := range pairs(resFields) {
		header.Add(name, value)
	}

	received := testTime().Add(offset)
	exch := exchange{
		res: &http.Response{
			Status:           "",
			StatusCode:       status,
			Proto:            "",
			ProtoMajor:       0,
			ProtoMinor:       0,
			Header:           header,
			Body:             nil,
			ContentLength:    0,
			TransferEncoding: nil,
			Close:            false,
			Uncompressed:     false,
			Trailer:          nil,
			Request:          nil,
			TLS:              nil,
		},
		requestTime:  received,
		responseTime: received,
	}

	return newVariant(newRequest(http.MethodGet, testURL, reqFields...), exch, false)
}

// matches reports whether v matches req, as the cache compares them.
func matches(v *variant, req *http.Request) bool {
	return v.matches(req, dialHost(req))
}

func TestVaryMatch(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-vary", "9111-4.1-vary-match")

	for _, test := range []struct {
		vary   string
		stored []string
		req    []string
		want   bool
	}{
		{"", nil, []string{hdrAccept, "x"}, true},
		{hdrAccept, []string{hdrAccept, "a"}, []string{hdrAccept, "a"}, true},
		{"accept", []string{hdrAccept, "a"}, []string{"ACCEPT", "a"}, true},
		{hdrAccept, []string{hdrAccept, "a"}, []string{hdrAccept, "b"}, false},
		{hdrAccept, []string{hdrAccept, "a"}, []string{hdrAccept, "A"}, false},
		{hdrAccept, []string{hdrAccept, "a, b"}, []string{hdrAccept, "b, a"}, false},
		{hdrAccept, []string{hdrAccept, "a, b"}, []string{hdrAccept, "a", hdrAccept, "b"}, true},
		{hdrAccept, []string{hdrAccept, "a"}, nil, false},
		{hdrAccept, nil, []string{hdrAccept, "a"}, false},
		{hdrAccept, nil, nil, true},
		{hdrAccept, []string{hdrAccept, ""}, nil, false},
		{varyAcceptFoo, []string{hdrAccept, "a", hdrFoo, "1"}, []string{hdrFoo, "1", hdrAccept, "a"}, true},
		{varyAcceptFoo, []string{hdrAccept, "a", hdrFoo, "1"}, []string{hdrAccept, "a", hdrFoo, "2"}, false},
		{varyAcceptFoo, []string{hdrAccept, "a", hdrFoo, "1"}, []string{hdrAccept, "a"}, false},
		{"*", nil, nil, false},
		{"*, *", nil, nil, false},
		{", *", nil, nil, false},
		{"Foo, *", nil, nil, false},
	} {
		v := testVariant(200, 0, test.stored, "Vary", test.vary)
		if got := matches(v, newRequest(http.MethodGet, testURL, test.req...)); got != test.want {
			t.Errorf("Vary %q, stored %q, request %q: matches = %t, want %t", test.vary, test.stored, test.req, got, test.want)
		}
	}

	// Vary on two field lines.
	stored := testVariant(200, 0, []string{hdrAccept, "a", hdrFoo, "1"}, "Vary", hdrAccept, "Vary", hdrFoo)
	if !matches(stored, newRequest(http.MethodGet, testURL, hdrAccept, "a", hdrFoo, "1")) ||
		matches(stored, newRequest(http.MethodGet, testURL, hdrAccept, "a", hdrFoo, "2")) {
		t.Error("Vary on two lines doesn't nominate both fields")
	}

	stored = testVariant(200, 0, nil, "Vary", hdrFoo, "Vary", "*")
	if matches(stored, newRequest(http.MethodGet, testURL)) {
		t.Error(`"*" on a second Vary line matched`)
	}
}

func FuzzVaryMatch(f *testing.F) {
	f.Add(varyAcceptFoo, "a", "b, c", "1")
	f.Add("*", "", "", "")
	f.Add("accept", "a,b", "a, b", "")

	f.Fuzz(func(t *testing.T, vary, a1, a2, b string) {
		reqA := newRequest(http.MethodGet, testURL)
		reqA.Header = http.Header{hdrAccept: {a1, a2}, hdrFoo: {b}}
		reqB := newRequest(http.MethodGet, testURL)
		reqB.Header = http.Header{hdrAccept: {a1 + ", " + a2}}

		varA := testVariant(200, 0, nil, "Vary", vary)
		varA.selection = selectionFor(reqA, varA.header)
		varB := testVariant(200, 0, nil, "Vary", vary)
		varB.selection = selectionFor(reqB, varB.header)

		if matches(varA, reqB) != matches(varB, reqA) {
			t.Fatalf("Vary %q: match isn't symmetric", vary)
		}

		if !varA.varyStar && !matches(varA, reqA) {
			t.Fatalf("Vary %q: response doesn't match its own request", vary)
		}
	})
}

func TestChoose(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4-most-recent", "9111-4.1-vary-omitted")

	when := func(d time.Duration) string { return formatHTTPDate(testTime().Add(d)) }
	req := newRequest(http.MethodGet, testURL, hdrAccept, "a")

	older := testVariant(200, 0, nil, hdrDate, when(0))
	newer := testVariant(200, time.Second, nil, hdrDate, when(time.Hour))

	ent := &entry{variants: []*variant{newer, older}}
	if got := ent.choose(req); got != newer {
		t.Error("didn't choose the response with the latest Date")
	}

	// With equal Dates, the later received wins.
	first := testVariant(200, 0, nil, hdrDate, when(0))
	second := testVariant(200, time.Second, nil, hdrDate, when(0))

	ent = &entry{variants: []*variant{second, first}}
	if got := ent.choose(req); got != second {
		t.Error("didn't break a Date tie by receive time")
	}

	// A matching response with Vary beats a newer one without.
	withVary := testVariant(200, 0, []string{hdrAccept, "a"}, hdrDate, when(0), "Vary", hdrAccept)

	ent = &entry{variants: []*variant{newer, withVary}}
	if got := ent.choose(req); got != withVary {
		t.Error("didn't prefer the response with a Vary field")
	}

	if got := ent.choose(newRequest(http.MethodGet, testURL, hdrAccept, "b")); got != newer {
		t.Error("didn't fall back to the response without Vary")
	}
}

func TestWithVariantLimit(t *testing.T) {
	t.Parallel()

	limits := newVariantLimits(defaultMaxVariants)

	var variants []*variant

	dropped := 0

	for i := range limits.perServer + 2 {
		v := testVariant(200, time.Duration(i)*time.Second, []string{hdrAccept, strconv.Itoa(i)},
			hdrDate, formatHTTPDate(testTime().Add(time.Duration(i)*time.Hour)), "Vary", hdrAccept)

		var n int

		variants, n = withVariant(variants, v, limits)
		dropped += n
	}

	if len(variants) != limits.perServer || dropped != 2 {
		t.Fatalf("got %d variants after dropping %d, want %d after dropping 2", len(variants), dropped, limits.perServer)
	}

	for _, v := range variants {
		if v.vary[0].value == "0" || v.vary[0].value == "1" {
			t.Errorf("the oldest variants weren't dropped: %q is stored", v.vary[0].value)
		}
	}

	// A response with the same Vary fields replaces the stored one.
	replacement := testVariant(200, time.Hour, []string{hdrAccept, "5"}, "Vary", hdrAccept)

	variants, dropped = withVariant(variants, replacement, limits)
	if n := len(variants); n != limits.perServer || dropped != 0 {
		t.Fatalf("after replacement, got %d variants after dropping %d", n, dropped)
	}

	if !slices.Contains(variants, replacement) {
		t.Error("replacement isn't stored")
	}
}

func TestWithVariantServers(t *testing.T) {
	t.Parallel()

	// Responses from different servers have separate limits, up to
	// limits.total in all.
	limits := newVariantLimits(defaultMaxVariants)

	var variants []*variant

	dropped := 0

	for server := range 10 {
		for i := range 7 {
			v := testVariant(200, time.Duration(server*7+i)*time.Second, []string{hdrAccept, strconv.Itoa(i)},
				hdrDate, formatHTTPDate(testTime().Add(time.Duration(server*7+i)*time.Hour)), "Vary", hdrAccept)
			v.dialHost = "10.0.0." + strconv.Itoa(server)

			var n int

			variants, n = withVariant(variants, v, limits)
			dropped += n
		}
	}

	if len(variants) != limits.total || dropped != 70-limits.total {
		t.Fatalf("got %d responses from 10 servers after dropping %d, want %d", len(variants), dropped, limits.total)
	}

	for _, v := range variants {
		if v.dialHost == "10.0.0.0" && v.vary[0].value != "6" {
			t.Errorf("response %s from the first server wasn't dropped", v.vary[0].value)
		}
	}
}

func TestNewVariantLimits(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		perServer, total int
	}{
		{1, serversPerTarget},
		{defaultMaxVariants, defaultMaxVariants * serversPerTarget},
		{math.MaxInt / serversPerTarget, math.MaxInt / serversPerTarget * serversPerTarget},
		// The total stops at math.MaxInt instead of overflowing.
		{math.MaxInt/serversPerTarget + 1, math.MaxInt},
		{math.MaxInt, math.MaxInt},
	} {
		want := variantLimits{perServer: test.perServer, total: test.total}
		if got := newVariantLimits(test.perServer); got != want {
			t.Errorf("newVariantLimits(%d) = %+v, want %+v", test.perServer, got, want)
		}
	}
}

// dateHeader returns a header with the Date field date, and the other fields
// given as name-value pairs.
func dateHeader(date string, fields ...string) http.Header {
	header := http.Header{hdrDate: {date}}
	for name, value := range pairs(fields) {
		header.Add(name, value)
	}

	return header
}

// identifyCase is the stored variants, the header of a 304, and the stored
// variant the cache sent a conditional request for, if any. It wants the
// indexes of the variants that identify returns.
type identifyCase struct {
	name     string
	variants []*variant
	header   http.Header
	sent     *variant
	want     []int
}

func TestFitBytes(t *testing.T) {
	t.Parallel()

	accepting := func(accept string, offset time.Duration) *variant {
		return testVariant(http.StatusOK, offset, []string{hdrAccept, accept}, "Vary", hdrAccept)
	}

	oldest, middle, newest := accepting("a", 0), accepting("b", time.Second), accepting("c", 2*time.Second)
	size := oldest.size()

	// The newest response is 4 times as large as the others.
	large := accepting("d", 3*time.Second)
	large.body = make([]byte, 3*size)

	variants := []*variant{newest, oldest, large, middle}
	given := slices.Clone(variants)

	for _, test := range []struct {
		limit int
		want  []*variant
	}{
		{7 * size, variants},
		{6 * size, []*variant{newest, large, middle}},
		{3 * size, []*variant{newest, oldest, middle}},
		{2 * size, []*variant{newest, middle}},
		{size, []*variant{newest}},
		{size - 1, []*variant{}},
	} {
		if got := fitBytes(variants, test.limit); !slices.Equal(got, test.want) {
			t.Errorf("limit %d: kept %d responses, want %d", test.limit, len(got), len(test.want))
		}
	}

	if !slices.Equal(variants, given) {
		t.Error("fitBytes modified the responses it was given")
	}
}

func TestContentLength(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		field string
		want  int64
	}{{"", -1}, {"0", 0}, {"5", 5}, {"-1", -1}, {"x", -1}} {
		header := make(http.Header)
		if test.field != "" {
			header.Set(hdrContentLength, test.field)
		}

		if got := contentLength(header); got != test.want {
			t.Errorf("Content-Length %q: contentLength = %d, want %d", test.field, got, test.want)
		}
	}
}

func TestWeigh(t *testing.T) {
	t.Parallel()

	varied := testVariant(http.StatusOK, 0, []string{hdrAccept, typeHTML}, "Vary", hdrAccept, hdrETag, etagA)
	varied.body = []byte(bodyHello)

	repeated := testVariant(http.StatusOK, 0, nil, hdrFoo, "a", hdrFoo, "bc", hdrETag, etagA)

	// The body, each field name once with all its values, and the request
	// field that Vary names.
	date := formatHTTPDate(testTime())
	want := len(bodyHello) + len("Vary"+hdrAccept) + len(hdrDate+date) + len(hdrETag+etagA) +
		len(hdrAccept+typeHTML) + len(hdrFoo+"a"+"bc") + len(hdrDate+date) + len(hdrETag+etagA)

	stored := &entry{variants: []*variant{varied, repeated}}
	if got := weigh(testURL, stored); got != want {
		t.Errorf("weigh = %d, want %d", got, want)
	}

	// A response loaded from a snapshot weighs the same.
	saved, _ := snapshotResponses(testURL, stored)
	loaded := &entry{variants: nil}

	for _, response := range saved {
		restored, _ := response.variant(false)
		loaded.variants = append(loaded.variants, restored)
	}

	if got := weigh(testURL, loaded); got != want {
		t.Errorf("weigh after loading = %d, want %d", got, want)
	}
}

func TestIdentify(t *testing.T) {
	t.Parallel()

	covers(t, "9111-4.3.4-strong")

	const lastMod = "Thu, 01 Jan 2026 00:00:00 GMT"

	later := formatHTTPDate(testTime().Add(time.Hour))
	req := newRequest(http.MethodGet, testURL)
	headers := func(fields ...string) http.Header { return dateHeader(later, fields...) }

	strongA := testVariant(200, 0, nil, hdrETag, etagA, hdrDate, later)
	strongA2 := testVariant(200, time.Second, nil, hdrETag, etagA, hdrDate, later)
	strongB := testVariant(200, 0, nil, hdrETag, etagB, hdrDate, later)
	weakA := testVariant(200, 0, nil, hdrETag, `W/"a"`, hdrDate, later)
	weakA2 := testVariant(200, time.Second, nil, hdrETag, `W/"a"`, hdrDate, later)
	withLM := testVariant(200, 0, nil, hdrLastModified, lastMod, hdrDate, later)
	withOtherLM := testVariant(200, 0, nil, hdrLastModified, later, hdrDate, later)
	sameSecondLM := testVariant(200, 0, nil, hdrLastModified, lastMod, hdrDate, lastMod)
	none := testVariant(200, 0, nil, hdrDate, later)
	otherVary := testVariant(200, 0, []string{hdrAccept, "x"}, hdrETag, etagA, "Vary", hdrAccept)

	for _, test := range []identifyCase{
		{
			"strong ETag updates every match", []*variant{strongA, strongB, strongA2},
			headers(hdrETag, etagA), nil, []int{0, 2},
		},
		{"strong ETag without a match updates nothing", []*variant{strongB}, headers(hdrETag, etagA), nil, nil},
		{"strong ETag doesn't match a weak one", []*variant{weakA}, headers(hdrETag, etagA), nil, nil},
		{"Vary mismatch is never updated", []*variant{otherVary}, headers(hdrETag, etagA), nil, nil},
		{"strong Last-Modified", []*variant{withLM, strongB}, headers(hdrLastModified, lastMod), nil, []int{0}},
		{
			"weak Last-Modified on the stored side",
			[]*variant{sameSecondLM}, headers(hdrLastModified, lastMod), nil, nil,
		},
		{
			"weak ETag updates the most recent match",
			[]*variant{weakA2, weakA, strongB}, headers(hdrETag, `W/"a"`), nil, []int{0},
		},
		{"weak ETag matches a strong one", []*variant{strongA}, headers(hdrETag, `W/"a"`), nil, []int{0}},
		{"weak validators without a match", []*variant{strongB}, headers(hdrETag, `W/"a"`), nil, nil},
		{
			"weak Last-Modified in the 304",
			[]*variant{sameSecondLM}, http.Header{hdrDate: {lastMod}, hdrLastModified: {lastMod}}, nil, []int{0},
		},
		{"no validators, lone response without one", []*variant{none}, headers(), nil, []int{0}},
		{"no validators, lone response with one", []*variant{strongA}, headers(), nil, nil},
		{"no validators, two responses", []*variant{none, none}, headers(), nil, nil},
		{"no validators, the cache's conditional", []*variant{strongB, strongA, weakA}, headers(), strongA, []int{1}},
		{"no validators, conditional for a replaced response", []*variant{strongB}, headers(), strongA, nil},
		{"no validators, conditional with Last-Modified", []*variant{withOtherLM, withLM}, headers(), withLM, []int{1}},
		{"strong ETag beats the cache's conditional", []*variant{strongA}, headers(hdrETag, etagB), strongA, nil},
	} {
		e := &entry{variants: test.variants}
		if got := e.identify(req, test.header, test.sent); !slices.Equal(got, test.want) {
			t.Errorf("%s: identify = %v, want %v", test.name, got, test.want)
		}
	}
}
