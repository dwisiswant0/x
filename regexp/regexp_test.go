package regexp

import (
	"testing"
)

func TestCompileEngineSelection(t *testing.T) {
	corePat := "a+"
	coreRe, err := Compile(corePat)
	if err != nil {
		t.Fatalf("compile core: %v", err)
	}
	if coreRe.core == nil || coreRe.pcre != nil {
		t.Fatalf("expected core backend for %q", corePat)
	}

	pcrePat := "(?<=a)b"
	pcreRe, err := Compile(pcrePat)
	if err != nil {
		t.Fatalf("compile pcre: %v", err)
	}
	if pcreRe.pcre == nil || pcreRe.core != nil {
		t.Fatalf("expected regexp2 backend for %q", pcrePat)
	}
}

func TestCoreMatchAndFind(t *testing.T) {
	re := MustCompile("a+")

	if !re.MatchString("caaab") {
		t.Fatalf("MatchString core: expected true")
	}

	if got := re.FindString("caaab"); got != "aaa" {
		t.Fatalf("FindString core: got %q", got)
	}

	if idx := re.FindStringIndex("caaab"); idx[0] != 1 || idx[1] != 4 {
		t.Fatalf("FindStringIndex core: got %v", idx)
	}

	reAlt := MustCompile("(a|ab)")
	if got := reAlt.FindString("ab"); got != "a" {
		t.Fatalf("FindString core alt (leftmost-first): got %q", got)
	}
	reAlt.Longest()
	if got := reAlt.FindString("ab"); got != "ab" {
		t.Fatalf("FindString core alt (longest): got %q", got)
	}
}

func TestPCREBackreference(t *testing.T) {
	re := MustCompile(`(\w+)\s+\1`)

	if re.core != nil {
		t.Fatalf("expected PCRE backend for backreference pattern")
	}

	if !re.MatchString("go go") {
		t.Fatalf("MatchString pcre backref: expected true")
	}

	if idx := re.FindStringIndex("go go"); idx[0] != 0 || idx[1] != 5 {
		t.Fatalf("FindStringIndex pcre backref: got %v", idx)
	}

	sm := re.FindStringSubmatch("go go")
	if len(sm) != 2 || sm[0] != "go go" || sm[1] != "go" {
		t.Fatalf("FindStringSubmatch pcre backref: got %v", sm)
	}

	idxs := re.FindStringSubmatchIndex("go go")
	expect := []int{0, 5, 0, 2}
	for i, v := range expect {
		if idxs[i] != v {
			t.Fatalf("FindStringSubmatchIndex pcre backref: got %v want %v", idxs, expect)
		}
	}
}

func TestPCRELookbehindRuneOffsets(t *testing.T) {
	// Emoji is 4 bytes; ensures rune-to-byte conversion is correct.
	re := MustCompile("(?<=🙂)a")

	input := "🙂a🙂a"
	idxs := re.FindStringIndex(input)
	if len(idxs) != 2 || idxs[0] != 4 || idxs[1] != 5 {
		t.Fatalf("FindStringIndex pcre lookbehind first: got %v", idxs)
	}

	all := re.FindAllStringIndex(input, -1)
	expect := [][]int{{4, 5}, {9, 10}}
	if len(all) != len(expect) {
		t.Fatalf("FindAllStringIndex pcre lookbehind len: got %v want %v", all, expect)
	}
	for i := range expect {
		if all[i][0] != expect[i][0] || all[i][1] != expect[i][1] {
			t.Fatalf("FindAllStringIndex pcre lookbehind[%d]: got %v want %v", i, all[i], expect[i])
		}
	}
}

func TestPCREReplaceAndSplit(t *testing.T) {
	re := MustCompile("(?<=a)b")

	if out := re.ReplaceAllString("ab ab", "X"); out != "aX aX" {
		t.Fatalf("ReplaceAllString pcre: got %q", out)
	}

	reComma := MustCompile(",")
	parts := reComma.Split("a,b,c", -1)
	expect := []string{"a", "b", "c"}
	if len(parts) != len(expect) {
		t.Fatalf("Split core len: got %v", parts)
	}
	for i := range expect {
		if parts[i] != expect[i] {
			t.Fatalf("Split core[%d]: got %q want %q", i, parts[i], expect[i])
		}
	}
}
