package regexp

import (
	"github.com/coregx/coregex"
	"github.com/dlclark/regexp2"
)

// Regexp is a compiled regular expression that delegates to either coregex
// (fast, RE2-compatible) or regexp2 (PCRE-compatible) depending on the
// pattern features detected at compile time.
type Regexp struct {
	pattern string
	core    *coregex.Regex
	pcre    *regexp2.Regexp
}

// Compile parses a regular expression and returns a compiled Regexp. Patterns
// that require PCRE/Perl-only features (detected by needsPCRE) are compiled
// with regexp2; everything else uses coregex for speed.
func Compile(pattern string) (*Regexp, error) {
	if needsPCRE(pattern) {
		re, err := regexp2.Compile(pattern, regexp2.None)
		if err != nil {
			return nil, err
		}
		return &Regexp{pattern: pattern, pcre: re}, nil
	}

	re, err := coregex.Compile(pattern)
	if err != nil {
		return nil, err
	}

	return &Regexp{pattern: pattern, core: re}, nil
}

// MustCompile is like Compile but panics if the expression cannot be parsed.
func MustCompile(pattern string) *Regexp {
	re, err := Compile(pattern)
	if err != nil {
		panic(err)
	}
	return re
}

// Match reports whether the byte slice b matches the regular expression
// pattern. This mirrors regexp.Match.
func Match(pattern string, b []byte) (bool, error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.Match(b), nil
}

// MatchString reports whether the string s matches the regular expression
// pattern. This mirrors regexp.MatchString.
func MatchString(pattern, s string) (bool, error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// QuoteMeta escapes all regular expression metacharacters in s.
func QuoteMeta(s string) string {
	return coregex.QuoteMeta(s)
}

// String returns the source pattern used to compile the Regexp.
func (r *Regexp) String() string {
	return r.pattern
}

// Match reports whether the byte slice b contains any match of the Regexp.
func (r *Regexp) Match(b []byte) bool {
	if r.core != nil {
		return r.core.Match(b)
	}

	matched, err := r.pcre.MatchString(string(b))
	return err == nil && matched
}

// MatchString reports whether the string s contains any match of the Regexp.
func (r *Regexp) MatchString(s string) bool {
	if r.core != nil {
		return r.core.MatchString(s)
	}

	matched, err := r.pcre.MatchString(s)
	return err == nil && matched
}

// Find returns the leftmost match of the Regexp in b.
func (r *Regexp) Find(b []byte) []byte {
	if r.core != nil {
		return r.core.Find(b)
	}

	m, err := r.pcre.FindStringMatch(string(b))
	if err != nil || m == nil {
		return nil
	}

	return []byte(m.String())
}

// FindString returns the leftmost match of the Regexp in s.
func (r *Regexp) FindString(s string) string {
	if r.core != nil {
		return r.core.FindString(s)
	}

	m, err := r.pcre.FindStringMatch(s)
	if err != nil || m == nil {
		return ""
	}

	return m.String()
}

// FindIndex returns a two-element slice with the start and end index of the
// leftmost match in b.
func (r *Regexp) FindIndex(b []byte) []int {
	if r.core != nil {
		return r.core.FindIndex(b)
	}

	return r.findStringIndex(string(b))
}

// FindStringIndex returns a two-element slice with the start and end index of
// the leftmost match in s.
func (r *Regexp) FindStringIndex(s string) []int {
	if r.core != nil {
		return r.core.FindStringIndex(s)
	}

	return r.findStringIndex(s)
}

// FindSubmatch returns slices identifying the leftmost match of the Regexp in
// b and its submatches.
func (r *Regexp) FindSubmatch(b []byte) [][]byte {
	if r.core != nil {
		return r.core.FindSubmatch(b)
	}

	matches := r.findStringSubmatch(string(b))
	if matches == nil {
		return nil
	}

	out := make([][]byte, len(matches))
	for i := range matches {
		out[i] = []byte(matches[i])
	}
	return out
}

// FindSubmatchIndex returns slices holding the index pairs identifying the
// leftmost match of the Regexp in b and its submatches.
func (r *Regexp) FindSubmatchIndex(b []byte) []int {
	if r.core != nil {
		return r.core.FindSubmatchIndex(b)
	}

	return r.findStringSubmatchIndex(string(b))
}

// FindStringSubmatch returns the leftmost match of the Regexp in s and its
// submatches as strings.
func (r *Regexp) FindStringSubmatch(s string) []string {
	if r.core != nil {
		return r.core.FindStringSubmatch(s)
	}

	return r.findStringSubmatch(s)
}

// FindStringSubmatchIndex returns the index pairs identifying the leftmost
// match of the Regexp in s and its submatches.
func (r *Regexp) FindStringSubmatchIndex(s string) []int {
	if r.core != nil {
		return r.core.FindStringSubmatchIndex(s)
	}

	return r.findStringSubmatchIndex(s)
}

// FindAll returns a slice of all successive matches of the Regexp in b.
func (r *Regexp) FindAll(b []byte, n int) [][]byte {
	if r.core != nil {
		return r.core.FindAll(b, n)
	}

	matches := r.findAllString(string(b), n)
	if matches == nil {
		return nil
	}

	out := make([][]byte, len(matches))
	for i := range matches {
		out[i] = []byte(matches[i])
	}
	return out
}

// FindAllIndex returns a slice of all successive match indices of the Regexp
// in b.
func (r *Regexp) FindAllIndex(b []byte, n int) [][]int {
	if r.core != nil {
		return r.core.FindAllIndex(b, n)
	}

	return r.findAllStringIndex(string(b), n)
}

// FindAllSubmatch returns a slice of all successive matches of the Regexp in b
// and their submatches.
func (r *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte {
	if r.core != nil {
		return r.core.FindAllSubmatch(b, n)
	}

	matches := r.findAllStringSubmatch(string(b), n)
	if matches == nil {
		return nil
	}

	out := make([][][]byte, len(matches))
	for i := range matches {
		out[i] = make([][]byte, len(matches[i]))
		for j := range matches[i] {
			out[i][j] = []byte(matches[i][j])
		}
	}
	return out
}

// FindAllSubmatchIndex returns a slice of all successive match index pairs of
// the Regexp in b and their submatches.
func (r *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	if r.core != nil {
		return r.core.FindAllSubmatchIndex(b, n)
	}

	return r.findAllStringSubmatchIndex(string(b), n)
}

// FindAllString returns a slice of all successive matches of the Regexp in s.
func (r *Regexp) FindAllString(s string, n int) []string {
	if r.core != nil {
		return r.core.FindAllString(s, n)
	}

	return r.findAllString(s, n)
}

// FindAllStringIndex returns a slice of all successive match indices of the
// Regexp in s.
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	if r.core != nil {
		return r.core.FindAllStringIndex(s, n)
	}

	return r.findAllStringIndex(s, n)
}

// FindAllStringSubmatch returns a slice of all successive matches of the
// Regexp in s and their submatches.
func (r *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	if r.core != nil {
		return r.core.FindAllStringSubmatch(s, n)
	}

	return r.findAllStringSubmatch(s, n)
}

// FindAllStringSubmatchIndex returns a slice of all successive match index
// pairs of the Regexp in s and their submatches.
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if r.core != nil {
		return r.core.FindAllStringSubmatchIndex(s, n)
	}

	return r.findAllStringSubmatchIndex(s, n)
}

// ReplaceAll returns a copy of src, replacing matches of the Regexp with repl.
func (r *Regexp) ReplaceAll(src []byte, repl []byte) []byte {
	if r.core != nil {
		return r.core.ReplaceAll(src, repl)
	}

	replaced, err := r.pcre.Replace(string(src), string(repl), -1, -1)
	if err != nil {
		return src
	}

	return []byte(replaced)
}

// ReplaceAllString returns a copy of src, replacing matches of the Regexp with
// repl.
func (r *Regexp) ReplaceAllString(src, repl string) string {
	if r.core != nil {
		return r.core.ReplaceAllString(src, repl)
	}

	replaced, err := r.pcre.Replace(src, repl, -1, -1)
	if err != nil {
		return src
	}

	return replaced
}

// Split slices s into substrings separated by the Regexp.
func (r *Regexp) Split(s string, n int) []string {
	if r.core != nil {
		return r.core.Split(s, n)
	}

	if n == 0 {
		return nil
	}

	parts := make([]string, 0)
	last := 0
	count := 0

	m, err := r.pcre.FindStringMatch(s)
	for err == nil && m != nil {
		if n > 0 && count+1 >= n {
			break
		}

		start, end := runeRangeToByte(s, m.Index, m.Length)
		parts = append(parts, s[last:start])
		last = end
		count++

		m, err = r.pcre.FindNextMatch(m)
	}

	parts = append(parts, s[last:])
	return parts
}

// NumSubexp returns the number of parenthesized subexpressions in this Regexp.
func (r *Regexp) NumSubexp() int {
	if r.core != nil {
		return r.core.NumSubexp()
	}

	nums := r.pcre.GetGroupNumbers()
	max := 0
	for _, v := range nums {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return 0
	}
	return max
}

// SubexpNames returns the names of the parenthesized subexpressions in this
// Regexp. The name for the first sub-expression is names[1].
func (r *Regexp) SubexpNames() []string {
	if r.core != nil {
		return r.core.SubexpNames()
	}

	nums := r.pcre.GetGroupNumbers()
	max := 0
	for _, v := range nums {
		if v > max {
			max = v
		}
	}

	names := make([]string, max+1)
	for i := 0; i <= max; i++ {
		names[i] = r.pcre.GroupNameFromNumber(i)
	}

	return names
}

func (r *Regexp) findStringIndex(s string) []int {
	m, err := r.pcre.FindStringMatch(s)
	if err != nil || m == nil {
		return nil
	}

	start, end := runeRangeToByte(s, m.Index, m.Length)
	return []int{start, end}
}

func (r *Regexp) findStringSubmatch(s string) []string {
	m, err := r.pcre.FindStringMatch(s)
	if err != nil || m == nil {
		return nil
	}

	return groupsToStrings(s, m.Groups())
}

func (r *Regexp) findStringSubmatchIndex(s string) []int {
	m, err := r.pcre.FindStringMatch(s)
	if err != nil || m == nil {
		return nil
	}

	return groupsToIndexes(s, m.Groups())
}

func (r *Regexp) findAllString(s string, n int) []string {
	matches := make([]string, 0)
	m, err := r.pcre.FindStringMatch(s)
	for err == nil && m != nil {
		if n >= 0 && len(matches) >= n {
			break
		}
		matches = append(matches, m.String())
		m, err = r.pcre.FindNextMatch(m)
	}
	return matches
}

func (r *Regexp) findAllStringIndex(s string, n int) [][]int {
	matches := make([][]int, 0)
	m, err := r.pcre.FindStringMatch(s)
	for err == nil && m != nil {
		if n >= 0 && len(matches) >= n {
			break
		}

		start, end := runeRangeToByte(s, m.Index, m.Length)
		matches = append(matches, []int{start, end})
		m, err = r.pcre.FindNextMatch(m)
	}

	return matches
}

func (r *Regexp) findAllStringSubmatch(s string, n int) [][]string {
	matches := make([][]string, 0)
	m, err := r.pcre.FindStringMatch(s)
	for err == nil && m != nil {
		if n >= 0 && len(matches) >= n {
			break
		}

		matches = append(matches, groupsToStrings(s, m.Groups()))
		m, err = r.pcre.FindNextMatch(m)
	}

	return matches
}

func (r *Regexp) findAllStringSubmatchIndex(s string, n int) [][]int {
	matches := make([][]int, 0)
	m, err := r.pcre.FindStringMatch(s)
	for err == nil && m != nil {
		if n >= 0 && len(matches) >= n {
			break
		}

		matches = append(matches, groupsToIndexes(s, m.Groups()))
		m, err = r.pcre.FindNextMatch(m)
	}

	return matches
}

func groupsToStrings(s string, groups []regexp2.Group) []string {
	out := make([]string, len(groups))
	runes := []rune(s)
	for i, g := range groups {
		if g.Index < 0 || g.Length < 0 {
			continue
		}
		out[i] = string(runes[g.Index : g.Index+g.Length])
	}
	return out
}

func groupsToIndexes(s string, groups []regexp2.Group) []int {
	out := make([]int, 0, len(groups)*2)
	for _, g := range groups {
		start, end := runeRangeToByte(s, g.Index, g.Length)
		out = append(out, start, end)
	}
	return out
}

func runeRangeToByte(s string, startRune, length int) (int, int) {
	if startRune < 0 || length < 0 {
		return -1, -1
	}

	start := runeToByteOffset(s, startRune)
	end := runeToByteOffset(s, startRune+length)
	return start, end
}

func runeToByteOffset(s string, runeIndex int) int {
	if runeIndex <= 0 {
		return 0
	}

	count := 0
	for i := range s {
		if count == runeIndex {
			return i
		}
		count++
	}

	return len(s)
}

// Longest switches the underlying engine to leftmost-longest matching when
// supported. coregex provides this directly; regexp2 is already PCRE-style and
// does not change behavior here.
func (r *Regexp) Longest() {
	if r.core != nil {
		r.core.Longest()
	}
}
