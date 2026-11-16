package cache

import (
	"bufio"
	"bytes"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestCacheTests runs the http-tests/cache-tests suite (https://cache-tests.fyi)
// against a shared cache in an httputil.ReverseProxy. Set CACHE_TESTS_DIR to a
// clone of https://github.com/http-tests/cache-tests with its npm dependencies
// installed. The suite needs Node.js.
//
// The test fails on any required test that fails, unless knownFailures lists
// it with the RFC text that contradicts the suite. It logs the other results:
// optional tests, behavior checks, and setup failures.
//
// To see the requests and responses of one suite test, set CACHE_TESTS_ID to
// its ID.
func TestCacheTests(t *testing.T) {
	t.Parallel()

	dir := os.Getenv("CACHE_TESTS_DIR")
	if dir == "" {
		t.Skip("CACHE_TESTS_DIR is not set")
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	args := []string{"run", "--silent", "cli", "--base=" + startSuiteProxy(t, dir)}
	cli := exec.CommandContext(t.Context(), "npm", args...) //nolint:gosec // G204: a fixed command and our proxy's URL
	cli.Dir = dir
	cli.Stderr = os.Stderr

	if id := os.Getenv("CACHE_TESTS_ID"); id != "" {
		// The CLI prints the exchanges and result of a single test.
		cli.Args = append(cli.Args, "--id="+id)
		cli.Stdout = os.Stdout

		err = cli.Run()
		if err != nil {
			t.Fatalf("cache-tests CLI: %v", err)
		}

		return
	}

	out, err := cli.Output()
	if err != nil {
		t.Fatalf("cache-tests CLI: %v", err)
	}

	known := knownFailures()
	byResult, failed := groupResults(t, known, summarize(t, dir, out))

	for id := range known {
		if !failed[id] {
			t.Errorf("%s is listed in knownFailures but didn't fail", id)
		}
	}

	logResults(t, byResult)
}

// startSuiteProxy starts the suite's origin server and a shared cache in an
// httputil.ReverseProxy in front of it, and returns the proxy's URL.
func startSuiteProxy(t *testing.T, dir string) string {
	t.Helper()

	originURL := startSuiteServer(t, dir)

	transport, err := New(newTransport(t, true), WithShared())
	if err != nil {
		t.Fatal(err)
	}

	// ReverseProxy.Director is deprecated, and a literal that lists every
	// field would have to name it.
	reverse := new(httputil.ReverseProxy)
	reverse.Rewrite = func(req *httputil.ProxyRequest) { req.SetURL(originURL) }
	reverse.Transport = transport

	proxy := httptest.NewServer(reverse)
	t.Cleanup(proxy.Close)

	return proxy.URL
}

// summarize returns the suite's results, which the CLI printed to out, as
// lines of a result, a test ID, and the test's name.
func summarize(t *testing.T, dir string, out []byte) []byte {
	t.Helper()

	resultsFile := filepath.Join(t.TempDir(), "results.json")

	err := os.WriteFile(resultsFile, out, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(t.TempDir(), "summarize.mjs")

	err = os.WriteFile(script, []byte(summarizeScript), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// G204: script is summarizeScript, and dir comes from CACHE_TESTS_DIR.
	summarizer := exec.CommandContext(t.Context(), "node", script, dir, resultsFile) //nolint:gosec // see above

	summary, err := summarizer.Output()
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}

	return summary
}

// groupResults groups the lines of summary by their result. It reports a
// required test that failed and knownFailures doesn't list, and returns the IDs
// of the tests that failed.
func groupResults(t *testing.T, known map[string]string, summary []byte) (map[string][]string, map[string]bool) {
	t.Helper()

	byResult := make(map[string][]string)
	failed := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(summary))
	for scanner.Scan() {
		result, rest, _ := strings.Cut(scanner.Text(), " ")
		byResult[result] = append(byResult[result], rest)

		if id, _, _ := strings.Cut(rest, " "); result == "fail" {
			failed[id] = true

			if _, ok := known[id]; !ok {
				t.Errorf("required test failed: %s", rest)
			}
		}
	}

	return byResult, failed
}

// logResults logs the number of tests with each result, and the tests that
// neither passed nor behaved as expected.
func logResults(t *testing.T, byResult map[string][]string) {
	t.Helper()

	results := make([]string, 0, len(byResult))
	for result := range byResult {
		results = append(results, result)
	}

	slices.Sort(results)

	for _, result := range results {
		ids := byResult[result]
		if result == "pass" || result == "yes" {
			t.Logf("%s: %d", result, len(ids))

			continue
		}

		t.Logf("%s: %d\n\t%s", result, len(ids), strings.Join(ids, "\n\t"))
	}
}

// startSuiteServer starts the suite's origin server on a free port and
// returns its URL. It runs node directly, rather than npm run server, so the
// server stops when the test kills it.
func startSuiteServer(t *testing.T, dir string) *url.URL {
	t.Helper()

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := listener.Addr().String()
	_ = listener.Close()
	_, port, _ := net.SplitHostPort(addr)

	server := exec.CommandContext(t.Context(), "node", "test-engine/server/server.mjs")
	server.Dir = dir

	server.Env = append(os.Environ(),
		"npm_package_config_protocol=http",
		"npm_package_config_port="+port,
		"npm_package_config_pidfile="+filepath.Join(t.TempDir(), "server.pid"),
	)
	server.Stderr = os.Stderr

	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	})

	var dialer net.Dialer

	for deadline := time.Now().Add(10 * time.Second); ; {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = conn.Close()

			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("cache-tests server didn't start: %v", err)
		}

		time.Sleep(50 * time.Millisecond)
	}

	originURL, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	return originURL
}

// knownFailures returns the required cache-tests that this cache fails on
// purpose, because the suite contradicts the RFCs, each with the RFC text that
// permits the cache's behavior.
//
// The suite runs its CDN-Cache-Control tests against every cache that isn't a
// browser cache. This cache isn't a CDN cache, so its target list is empty,
// and RFC 9213 §2.2 says: "Targeted fields that are not on a cache's target
// list MUST NOT change that cache's behavior and MUST be passed through".
func knownFailures() map[string]string {
	const targeted = "RFC 9213 §2.2: CDN-Cache-Control MUST NOT change this cache's behavior; "

	return map[string]string{
		"cdn-private":           targeted + "Cache-Control: max-age=10000 makes it fresh (RFC 9111 §4.2.1)",
		"cdn-no-cache":          targeted + "Cache-Control: max-age=10000 makes it fresh (RFC 9111 §4.2.1)",
		"cdn-no-store-cc-fresh": targeted + "Cache-Control: max-age=10000 lets it be stored (RFC 9111 §3)",
		"cdn-fresh-cc-nostore":  targeted + "Cache-Control: no-store forbids storing (RFC 9111 §5.2.2.5)",
	}
}

// summarizeScript prints the result of each test in a cache-tests results
// file, one per line as "<result> <test ID> [<details>]", where result names
// a key of the suite's resultTypes: pass, fail, optional_fail, yes, no,
// setup_fail, and so on. "fail" is a required test that didn't pass.
// The test runs it as "node summarize.mjs <cache-tests directory>
// <results.json>".
const summarizeScript = `import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const [dir, resultsFile] = process.argv.slice(2)
const load = (path) => import(pathToFileURL(join(dir, path)).href)

const { default: suites } = await load('tests/index.mjs')
const { determineTestResult, parseResults, resultTypes } = await load('test-engine/lib/results.mjs')

const { results } = parseResults(JSON.parse(readFileSync(resultsFile, 'utf8')))
const names = new Map(Object.entries(resultTypes).map(([name, type]) => [type, name]))

for (const suite of suites) {
  for (const test of suite.tests) {
    if (test.id in results) {
      const result = names.get(determineTestResult(suites, test.id, results))
      const details = Array.isArray(results[test.id]) ? results[test.id].slice(1).join(': ') : ''
      console.log((result + ' ' + test.id + ' ' + details).trimEnd())
    }
  }
}
`
