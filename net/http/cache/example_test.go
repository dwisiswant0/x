package cache_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	"go.dw1.io/x/net/http/cache" //nolint:depguard // depguard has no allowlist without a config
)

func ExampleNew() {
	var requests atomic.Int32

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Cache-Control", "max-age=60")
		_, _ = io.WriteString(writer, "hello")
	}))
	defer origin.Close()

	transport, err := cache.New(nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	client := &http.Client{Transport: transport, CheckRedirect: nil, Jar: nil, Timeout: 0}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	for range 2 {
		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)

			return
		}

		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		fmt.Printf("%s, Age %q\n", body, res.Header.Get("Age"))
	}

	fmt.Println("origin requests:", requests.Load())
	// Output:
	// hello, Age ""
	// hello, Age "0"
	// origin requests: 1
}

func ExampleWithShared() {
	var requests atomic.Int32

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Cache-Control", "s-maxage=60")
		_, _ = io.WriteString(writer, "hello")
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		fmt.Println(err)

		return
	}

	// Don't let Go's transport decode gzip, so the proxy forwards content
	// unchanged (RFC 9110 §7.7).
	upstream, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		fmt.Println("http.DefaultTransport isn't an *http.Transport")

		return
	}

	upstream = upstream.Clone()
	upstream.DisableCompression = true

	transport, err := cache.New(upstream, cache.WithShared())
	if err != nil {
		fmt.Println(err)

		return
	}

	reverse := new(httputil.ReverseProxy)
	reverse.Rewrite = func(r *httputil.ProxyRequest) { r.SetURL(target) }
	reverse.Transport = transport

	proxy := httptest.NewServer(reverse)
	defer proxy.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, proxy.URL, nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	for range 3 {
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println(err)

			return
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}

	fmt.Println("origin requests:", requests.Load())
	// Output:
	// origin requests: 1
}

func ExampleTransport_Save() {
	var full, notModified atomic.Int32

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set("Cache-Control", "max-age=3600")
		writer.Header().Set("ETag", `"v1"`)

		if req.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			writer.WriteHeader(http.StatusNotModified)

			return
		}

		full.Add(1)

		_, _ = io.WriteString(writer, "hello")
	}))
	defer origin.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	// Each iteration stands for one run of a program, which loads the
	// snapshot the previous run saved. A real program would keep it in a file
	// that only its owner can read and write. The loaded response is
	// validated before its first use, and the 304 saves sending the body
	// again.
	var snapshot bytes.Buffer

	for run := range 2 {
		transport, err := cache.New(nil)
		if err == nil && run > 0 {
			err = transport.Load(&snapshot)
		}

		var res *http.Response
		if err == nil {
			res, err = transport.RoundTrip(req)
		}

		if err != nil {
			fmt.Println(err)

			return
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		snapshot.Reset()

		err = transport.Save(&snapshot)
		if err != nil {
			fmt.Println(err)

			return
		}
	}

	fmt.Println("full responses:", full.Load())
	fmt.Println("304 responses:", notModified.Load())
	// Output:
	// full responses: 1
	// 304 responses: 1
}

func ExampleTransport_Stats() {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "max-age=60")
		_, _ = io.WriteString(writer, "hello")
	}))
	defer origin.Close()

	transport, err := cache.New(nil)
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, path := range []string{"/a", "/a", "/b", "/a"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+path, nil)
		if err != nil {
			fmt.Println(err)

			return
		}

		res, err := transport.RoundTrip(req)
		if err != nil {
			fmt.Println(err)

			return
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}

	stats := transport.Stats()
	requests := stats.Hits + stats.Revalidations + stats.Misses + stats.Bypasses
	fmt.Printf("answered %d of %d requests from the cache\n", stats.Hits+stats.Revalidations, requests)
	fmt.Println("stored responses:", stats.Stores)
	// Output:
	// answered 2 of 4 requests from the cache
	// stored responses: 2
}

func ExampleTransport_WithNext() {
	var requests atomic.Int32

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("Cache-Control", "max-age=3600")
		_, _ = io.WriteString(writer, "hello")
	}))
	defer origin.Close()

	upstream, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		fmt.Println("http.DefaultTransport isn't an *http.Transport")

		return
	}

	// The two clients need transports with different settings, here their
	// proxies, but request the same URLs.
	direct := upstream.Clone()
	direct.Proxy = nil

	transport, err := cache.New(upstream.Clone())
	if err != nil {
		fmt.Println(err)

		return
	}

	clients := []*http.Client{
		{Transport: transport, CheckRedirect: nil, Jar: nil, Timeout: 0},
		{Transport: transport.WithNext(direct), CheckRedirect: nil, Jar: nil, Timeout: 0},
	}

	for _, client := range clients {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+"/home", nil)
		if err != nil {
			fmt.Println(err)

			return
		}

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)

			return
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}

	fmt.Println("origin requests:", requests.Load())
	// Output:
	// origin requests: 1
}
