package cache

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// staticOrigin answers every request with the same response, cheaply, so the
// benchmarks measure the cache.
type staticOrigin struct {
	header http.Header
	body   []byte
}

func (o *staticOrigin) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:           "200 OK",
		StatusCode:       http.StatusOK,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           o.header.Clone(),
		Body:             io.NopCloser(bytes.NewReader(o.body)),
		ContentLength:    int64(len(o.body)),
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     false,
		Trailer:          nil,
		Request:          req,
		TLS:              nil,
	}, nil
}

func benchCache(b *testing.B, fields ...string) *Transport {
	b.Helper()

	srv := &staticOrigin{header: make(http.Header), body: []byte(strings.Repeat("x", 1024))}
	for name, value := range pairs(fields) {
		srv.header.Add(name, value)
	}

	cache, err := New(srv)
	if err != nil {
		b.Fatal(err)
	}

	return cache
}

// drain sends req through cache and discards the response body. It panics
// on a transport error instead of taking a testing.B, because the benchmarks
// call it in their timed loops and testing.B.Helper isn't free.
func drain(cache *Transport, req *http.Request) {
	res, err := cache.RoundTrip(req)
	if err != nil {
		panic(err)
	}

	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

func BenchmarkRoundTrip(b *testing.B) {
	b.Run("hit", func(b *testing.B) {
		cache := benchCache(b, hdrCacheControl, "max-age=3600")
		req := newRequest(http.MethodGet, testURL)
		drain(cache, req)

		b.ReportAllocs()

		for b.Loop() {
			drain(cache, req)
		}
	})

	b.Run("hit-parallel", func(b *testing.B) {
		cache := benchCache(b, hdrCacheControl, "max-age=3600")
		drain(cache, newRequest(http.MethodGet, testURL))

		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			req := newRequest(http.MethodGet, testURL)
			for pb.Next() {
				drain(cache, req)
			}
		})
	})

	b.Run("miss-store", func(b *testing.B) {
		cache := benchCache(b, hdrCacheControl, "max-age=3600")
		// no-cache forwards every request, and each response replaces the
		// stored one.
		req := newRequest(http.MethodGet, testURL, hdrCacheControl, ccNoCache)

		b.ReportAllocs()

		for b.Loop() {
			drain(cache, req)
		}
	})

	b.Run("vary-hit", func(b *testing.B) {
		cache := benchCache(b, hdrCacheControl, "max-age=3600", "Vary", "Accept-Encoding, Accept-Language")
		for _, enc := range []string{"gzip", "br", "zstd", "identity"} {
			drain(cache, newRequest(http.MethodGet, testURL, "Accept-Encoding", enc, "Accept-Language", "en"))
		}

		req := newRequest(http.MethodGet, testURL, "Accept-Encoding", "zstd", "Accept-Language", "en")

		b.ReportAllocs()

		for b.Loop() {
			drain(cache, req)
		}
	})
}
