package cache

import (
	"net/http"
	"strings"
)

// target is the scheme and authority of a request's target URI (RFC 9110
// §7.1), which with the path and query form its cache key.
type target struct {
	scheme    string
	authority string
}

// newTarget returns the target of req, whose authority is req.Host if set and
// req.URL.Host otherwise. It reports false for schemes other than http and
// https, whose responses aren't cached.
func newTarget(req *http.Request) (target, bool) {
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return target{scheme: "", authority: ""}, false
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	t := target{scheme: scheme, authority: normalizeHost(scheme, host)}

	return t, t.authority != ""
}

// key returns the cache key of the URI with this target's scheme and
// authority and the given path and query.
func (t target) key(requestURI string) string {
	return t.scheme + "://" + t.authority + requestURI
}

// resolve returns the cache key of a URI reference from a response field,
// such as Location, resolved against req's target URI. It reports false if
// the reference is invalid or has a different origin, which RFC 9111 §4.4
// forbids invalidating.
func (t target) resolve(req *http.Request, ref string) (string, bool) {
	if ref == "" {
		return "", false
	}

	base := *req.URL
	base.Scheme, base.Host, base.User = t.scheme, t.authority, nil

	u, err := base.Parse(ref)
	if err != nil || u.Scheme != t.scheme || normalizeHost(t.scheme, u.Host) != t.authority {
		return "", false
	}

	return t.key(u.RequestURI()), true
}

// dialHost returns req.URL.Host when the request is sent to a server other
// than the authority of its target URI, as a proxy that sets Host does, and
// "" otherwise. A stored response is reused only for requests sent to the
// same server, so backends that share a Host header don't share responses.
func dialHost(req *http.Request) string {
	if req.Host == "" {
		return ""
	}

	scheme := strings.ToLower(req.URL.Scheme)
	if dial := normalizeHost(scheme, req.URL.Host); dial != normalizeHost(scheme, req.Host) {
		return dial
	}

	return ""
}

// normalizeHost lowercases an authority and removes the scheme's default
// port, so equivalent URIs share a key (RFC 9110 §4.2.3).
func normalizeHost(scheme, host string) string {
	host = strings.ToLower(host)

	switch scheme {
	case "http":
		host = strings.TrimSuffix(host, ":80")
	case "https":
		host = strings.TrimSuffix(host, ":443")
	}

	return strings.TrimSuffix(host, ":")
}
