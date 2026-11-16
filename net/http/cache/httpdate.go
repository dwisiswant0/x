package cache

import (
	"net/http"
	"strings"
	"time"
)

const (
	// dayNames and monthNames pack the three-letter names of RFC 9110
	// §5.6.7, lowercased.
	dayNames   = "sunmontuewedthufrisat"
	monthNames = "janfebmaraprmayjunjulaugsepoctnovdec"
	nameLen    = 3

	// An RFC 850 date's two-digit year names the year with those digits
	// that is at most rfc850Window years after now (RFC 9110 §5.6.7).
	rfc850Window = 50
	century      = 100

	// maxYear is the largest year an IMF-fixdate can hold.
	maxYear = 9999

	decimalBase = 10
)

// formatHTTPDate formats t as an IMF-fixdate, the only HTTP-date format a
// sender may generate (RFC 9110 §5.6.7).
func formatHTTPDate(t time.Time) string {
	return t.UTC().Format(http.TimeFormat)
}

// parseHTTPDate parses an HTTP-date in any of the three formats of RFC 9110
// §5.6.7. Names are matched case-insensitively and the zone must be GMT
// (RFC 9111 §4.2).
//
// It doesn't use [http.ParseTime], which accepts extra spaces and one-digit
// hours, and whose RFC 850 layout resolves the zone against [time.Local].
func parseHTTPDate(text string) (time.Time, bool) {
	switch {
	case len(text) == len("Sun, 06 Nov 1994 08:49:37 GMT") && text[3] == ',':
		return parseIMFFixdate(text)
	case len(text) == len("Sun Nov  6 08:49:37 1994"):
		return parseAsctime(text)
	default:
		return parseRFC850(text, time.Now())
	}
}

// parseIMFFixdate parses "Sun, 06 Nov 1994 08:49:37 GMT".
func parseIMFFixdate(text string) (time.Time, bool) {
	if !isDayName(text[:3]) || text[3:5] != ", " || text[7] != ' ' || text[11] != ' ' ||
		text[16] != ' ' || !strings.EqualFold(text[25:], " GMT") {
		return time.Time{}, false
	}

	day, dayOK := atoi(text[5:7])
	month, monthOK := monthIndex(text[8:11])
	year, yearOK := atoi(text[12:16])

	if !dayOK || !monthOK || !yearOK {
		return time.Time{}, false
	}

	return newDate(year, month, day, text[17:25])
}

// parseRFC850 parses "Sunday, 06-Nov-94 08:49:37 GMT".
func parseRFC850(text string, now time.Time) (time.Time, bool) {
	name, rest, found := strings.Cut(text, ",")
	if !found || !isLongDayName(name) || !hasRFC850Layout(rest) {
		return time.Time{}, false
	}

	day, dayOK := atoi(rest[1:3])
	month, monthOK := monthIndex(rest[4:7])
	twoDigitYear, yearOK := atoi(rest[8:10])

	if !dayOK || !monthOK || !yearOK {
		return time.Time{}, false
	}

	return placeTwoDigitYear(now, twoDigitYear, month, day, rest[11:19])
}

// hasRFC850Layout reports whether rest, the part of an RFC 850 date after the
// day name, has the layout " 06-Nov-94 08:49:37 GMT".
func hasRFC850Layout(rest string) bool {
	return len(rest) == len(" 06-Nov-94 08:49:37 GMT") && rest[0] == ' ' && rest[3] == '-' &&
		rest[7] == '-' && rest[10] == ' ' && strings.EqualFold(rest[19:], " GMT")
}

// placeTwoDigitYear returns the date with the year ending in twoDigitYear
// that falls within 50 years of now, rather than in a fixed century. RFC 9110
// §5.6.7 says a year more than 50 years after now means the most recent past
// year with those digits.
func placeTwoDigitYear(now time.Time, twoDigitYear int, month time.Month, day int, clock string) (time.Time, bool) {
	year := now.Year() - now.Year()%century + twoDigitYear

	date, valid := newDate(year, month, day, clock)
	limit := now.AddDate(rfc850Window, 0, 0)

	switch {
	case !valid:
		return time.Time{}, false
	case date.After(limit):
		return newDate(year-century, month, day, clock)
	case !date.AddDate(century, 0, 0).After(limit):
		return newDate(year+century, month, day, clock)
	}

	return date, true
}

// parseAsctime parses "Sun Nov  6 08:49:37 1994", which has no zone and is
// read as GMT.
func parseAsctime(text string) (time.Time, bool) {
	if !isDayName(text[:3]) || text[3] != ' ' || text[7] != ' ' || text[10] != ' ' || text[19] != ' ' {
		return time.Time{}, false
	}

	month, monthOK := monthIndex(text[4:7])
	day, dayOK := atoi(strings.TrimPrefix(text[8:10], " "))
	year, yearOK := atoi(text[20:24])

	if !monthOK || !dayOK || !yearOK {
		return time.Time{}, false
	}

	return newDate(year, month, day, text[11:19])
}

// newDate validates a calendar date and an "hh:mm:ss" time of day and returns
// them as a UTC time.
func newDate(year int, month time.Month, day int, clock string) (time.Time, bool) {
	hour, minute, sec, valid := parseClock(clock)
	if !valid || day < 1 || day > daysIn(year, month) {
		return time.Time{}, false
	}

	date := time.Date(year, month, day, hour, minute, sec, 0, time.UTC)

	// A leap second at the end of 9999 would need a five-digit year, which
	// an IMF-fixdate can't hold.
	return date, date.Year() <= maxYear
}

// parseClock parses an "hh:mm:ss" time of day into its hour, minute, and
// second. A second of 60 is a leap second, which time.Date normalizes.
func parseClock(clock string) (int, int, int, bool) {
	if len(clock) != len("08:49:37") || clock[2] != ':' || clock[5] != ':' {
		return 0, 0, 0, false
	}

	hour, hourOK := atoi(clock[0:2])
	minute, minuteOK := atoi(clock[3:5])
	sec, secOK := atoi(clock[6:8])

	return hour, minute, sec, hourOK && minuteOK && secOK && hour <= 23 && minute <= 59 && sec <= 60
}

func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isDayName(name string) bool {
	return nameIndex(dayNames, name) >= 0
}

func isLongDayName(name string) bool {
	switch strings.ToLower(name) {
	case "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday":
		return true
	}

	return false
}

func monthIndex(name string) (time.Month, bool) {
	index := nameIndex(monthNames, name)

	return time.Month(index + 1), index >= 0
}

// nameIndex returns the position of name among the three-letter names packed
// in names, compared case-insensitively, or -1 if it isn't one of them.
func nameIndex(names, name string) int {
	if len(name) != nameLen {
		return -1
	}

	for pos := 0; pos < len(names); pos += nameLen {
		if strings.EqualFold(names[pos:pos+nameLen], name) {
			return pos / nameLen
		}
	}

	return -1
}

// atoi parses a non-empty string of ASCII digits.
func atoi(digits string) (int, bool) {
	if digits == "" {
		return 0, false
	}

	num := 0

	for pos := range len(digits) {
		char := digits[pos]
		if char < '0' || char > '9' {
			return 0, false
		}

		num = num*decimalBase + int(char-'0')
	}

	return num, true
}
