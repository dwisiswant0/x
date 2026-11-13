package regexp

import (
	"strings"
	"testing"
)

var benchmarkSubmatches []string

func BenchmarkPCREFindStringSubmatchLongInput(b *testing.B) {
	re := MustCompile(`(\w+)\s+\1`)
	input := "target target " + strings.Repeat("x", 64*1024)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()

	for b.Loop() {
		benchmarkSubmatches = re.FindStringSubmatch(input)
	}
}
