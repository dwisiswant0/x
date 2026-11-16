package cache

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	errFieldCount    = errors.New("want 5 fields")
	errDuplicateID   = errors.New("duplicate ID")
	errInvalidStatus = errors.New("invalid status")
)

// requirements maps each ID in requirementsTable to whether a test must
// cover it.
//
//nolint:gochecknoglobals // TestMain reads it after the tests have run
var requirements = sync.OnceValues(func() (map[string]bool, error) {
	reqs := make(map[string]bool)

	for idx, text := range requirementEntries(requirementsTable) {
		if strings.HasPrefix(text, "#") {
			continue
		}

		num := idx + 1

		fields := strings.SplitN(text, " | ", 5)
		if len(fields) != 5 {
			return nil, fmt.Errorf("requirement %d: %w, got %d", num, errFieldCount, len(fields))
		}

		reqID, status := fields[0], fields[3]
		if _, dup := reqs[reqID]; dup {
			return nil, fmt.Errorf("requirement %d: %w %q", num, errDuplicateID, reqID)
		}

		if status != "test" && !strings.HasPrefix(status, "n/a: ") && !strings.HasPrefix(status, "deviation: ") {
			return nil, fmt.Errorf("requirement %d: %w %q", num, errInvalidStatus, status)
		}

		reqs[reqID] = status == "test"
	}

	return reqs, nil
})

// requirementEntries returns the entries of a requirements table, with each
// continuation line joined to its entry and blank lines left out.
func requirementEntries(table string) []string {
	var entries []string

	for line := range strings.SplitSeq(table, "\n") {
		switch {
		case strings.HasPrefix(line, "\t") && len(entries) > 0:
			entries[len(entries)-1] += " " + line[1:]
		case line != "":
			entries = append(entries, line)
		}
	}

	return entries
}

var (
	coveredMu sync.Mutex              //nolint:gochecknoglobals // TestMain reads covered after the tests have run
	covered   = make(map[string]bool) //nolint:gochecknoglobals // TestMain reads covered after the tests have run
)

// covers records that the calling test checks the requirements with the
// given IDs from requirementsTable.
func covers(tb testing.TB, ids ...string) {
	tb.Helper()

	reqs, err := requirements()
	if err != nil {
		tb.Fatal(err)
	}

	for _, reqID := range ids {
		testable, ok := reqs[reqID]

		switch {
		case !ok:
			tb.Fatalf("covers: unknown requirement %q", reqID)
		case !testable:
			tb.Fatalf("covers: requirement %q is marked n/a or deviation", reqID)
		}
	}

	coveredMu.Lock()
	defer coveredMu.Unlock()

	for _, id := range ids {
		covered[id] = true
	}
}

// TestMain fails a full test run in which some testable requirement has no
// covering test. An empty list of uncovered requirements is the compliance
// signal.
func TestMain(m *testing.M) {
	code := m.Run()
	if code != 0 || !fullRun() {
		os.Exit(code)
	}

	reqs, err := requirements()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var missing []string

	for id, testable := range reqs {
		if testable && !covered[id] {
			missing = append(missing, id)
		}
	}

	if len(missing) > 0 {
		slices.Sort(missing)
		fmt.Fprintf(os.Stderr, "FAIL: requirements without a covering test:\n\t%s\n", strings.Join(missing, "\n\t"))
		os.Exit(1)
	}

	os.Exit(0)
}

// fullRun reports whether the test binary ran every test, so that coverage
// is meaningful.
func fullRun() bool {
	for _, name := range []string{"test.run", "test.skip", "test.list"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != "" {
			return false
		}
	}

	return true
}
