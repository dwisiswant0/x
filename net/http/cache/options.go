package cache

import "fmt"

const (
	defaultMaxEntries  = 4096
	defaultMaxBodySize = 1 << 20
	defaultMaxVariants = 8
	defaultMaxBytes    = 64 << 20
)

type config struct {
	shared      bool
	maxEntries  int
	maxBodySize int64
	maxVariants int
	maxBytes    int64
}

// Option configures a [Transport]. [New] applies options in order and returns
// the first error.
type Option func(*config) error

// WithShared makes the Transport a shared cache (RFC 9111 §1), for use as the
// Transport of an [httputil.ReverseProxy] or another proxy that serves many
// users. A shared cache:
//
//   - Doesn't store a response marked private.
//   - Stores a response to a request with Authorization only if public,
//     must-revalidate, or s-maxage allows it.
//   - Uses s-maxage in place of max-age.
//   - Never serves a stale response marked proxy-revalidate or s-maxage.
//
// [httputil.ReverseProxy]: https://pkg.go.dev/net/http/httputil#ReverseProxy
func WithShared() Option {
	return func(cfg *config) error {
		cfg.shared = true

		return nil
	}
}

// WithMaxEntries sets how many target URIs the cache holds. entries must be
// positive. The default is 4096.
//
// When the cache is full, the target URI stored first is evicted first.
// [WithMaxVariants] sets how many responses each target URI holds, and
// [WithMaxBytes] how many bytes of responses the cache holds in all.
func WithMaxEntries(entries int) Option {
	return func(cfg *config) error {
		if entries <= 0 {
			return fmt.Errorf("%w: max entries must be positive, got %d", ErrInvalidOption, entries)
		}

		cfg.maxEntries = entries

		return nil
	}
}

// WithMaxBodySize sets the size, in bytes, of the largest response body the
// cache stores. size must not be negative. The default is 1 MiB.
//
// Larger bodies stream to the caller and aren't stored.
func WithMaxBodySize(size int64) Option {
	return func(cfg *config) error {
		if size < 0 {
			return fmt.Errorf("%w: max body size must not be negative, got %d", ErrInvalidOption, size)
		}

		cfg.maxBodySize = size

		return nil
	}
}

// WithMaxVariants sets how many responses each target URI holds from one
// server for requests that differ by the fields its Vary header names.
// variants must be positive. The default is 8.
//
// Past that, the oldest of them is dropped. A target URI holds at most 8
// times that many responses in all, so that a proxy that spreads one Host
// over several servers keeps their responses side by side. A request is
// compared with every response its target URI holds, so a large limit slows
// down requests for a resource that varies on a field with many values.
func WithMaxVariants(variants int) Option {
	return func(cfg *config) error {
		if variants <= 0 {
			return fmt.Errorf("%w: max variants must be positive, got %d", ErrInvalidOption, variants)
		}

		cfg.maxVariants = variants

		return nil
	}
}

// WithMaxBytes sets how many bytes of responses the cache holds, counting
// their bodies, their header fields, and the request fields that their Vary
// headers name. size must be positive. The default is 64 MiB.
//
// Memory use is higher than the count, which leaves out Go's own overhead,
// and each body that is still arriving takes up to [WithMaxBodySize] bytes
// more, or size if that is smaller, until it is stored. A response larger
// than size is never stored.
//
// When a response doesn't fit, the target URIs stored first are evicted first,
// as many as it takes, so a response much larger than most can evict many of
// them at once. A target URI whose responses don't fit together drops its
// oldest ones until they do.
func WithMaxBytes(size int64) Option {
	return func(cfg *config) error {
		if size <= 0 {
			return fmt.Errorf("%w: max bytes must be positive, got %d", ErrInvalidOption, size)
		}

		cfg.maxBytes = size

		return nil
	}
}
