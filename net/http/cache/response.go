package cache

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"
)

// response returns v as a response to req, with the given header, which the
// response owns.
func (v *variant) response(req *http.Request, header http.Header) *http.Response {
	body := io.ReadCloser(http.NoBody)
	if req.Method != http.MethodHead && len(v.body) > 0 {
		stored := new(storedBody)
		stored.Reset(v.body)
		body = stored
	}

	return newResponse(req, v.status, v.statusText, header, body, int64(len(v.body)), v.decoded)
}

// storedBody serves a stored body. It costs one allocation, where
// io.NopCloser(bytes.NewReader(body)) costs two, and like that it keeps
// bytes.Reader's WriteTo.
type storedBody struct {
	bytes.Reader
}

func (*storedBody) Close() error {
	return nil
}

// hit returns the response to req that v satisfies without contacting the
// origin: a 304 if req's own preconditions say the client's copy is current
// (RFC 9111 §4.3.2), and v otherwise. Either carries an Age field that
// replaces any stored one (§4).
func (v *variant) hit(req *http.Request, age time.Duration) *http.Response {
	ageValue := strconv.FormatInt(int64(age/time.Second), 10)

	if notModified(req, v) {
		res := v.notModifiedResponse(req)
		res.Header.Set("Age", ageValue)

		return res
	}

	return v.response(req, withAge(v.header, ageValue))
}

// withAge returns a copy of header with an Age field of age in place of any
// stored one. Unlike Header.Clone followed by Header.Set, it makes room for
// Age up front, which saves an allocation and, for a header with exactly 8
// fields, the growth of the map past its smallest size.
func withAge(header http.Header, age string) http.Header {
	count := 1

	for name, values := range header {
		if name != "Age" {
			count += len(values)
		}
	}

	// As in Header.Clone, every value shares one backing array.
	all := make([]string, count)
	out := make(http.Header, len(header)+1)

	for name, values := range header {
		switch {
		case name == "Age":
		case values == nil:
			out[name] = nil
		default:
			n := copy(all, values)
			out[name], all = all[:n:n], all[n:]
		}
	}

	all[0] = age
	out["Age"] = all[:1:1]

	return out
}

// notModifiedResponse returns a 304 for v with the fields RFC 9110 §15.4.5
// requires. Last-Modified is included only when there is no ETag, the case
// in which §15.4.5 says it helps the client update its copy.
func (v *variant) notModifiedResponse(req *http.Request) *http.Response {
	names := []string{"Cache-Control", "Content-Location", "Date", "ETag", "Expires", "Vary"}
	if len(v.header.Values("ETag")) == 0 {
		names = append(names, "Last-Modified")
	}

	header := make(http.Header, len(names)+1)

	for _, name := range names {
		for _, value := range v.header.Values(name) {
			header.Add(name, value)
		}
	}

	return newResponse(req, http.StatusNotModified, "304 Not Modified", header, http.NoBody, 0, false)
}

// gatewayTimeout returns the 504 that answers an only-if-cached request the
// cache can't satisfy (RFC 9111 §5.2.1.7).
func gatewayTimeout(req *http.Request, now time.Time) *http.Response {
	header := http.Header{"Date": {formatHTTPDate(now)}}

	return newResponse(req, http.StatusGatewayTimeout, "504 Gateway Timeout", header, http.NoBody, 0, false)
}

// newResponse returns a response to req that the cache generates.
func newResponse(
	req *http.Request,
	status int,
	statusText string,
	header http.Header,
	body io.ReadCloser,
	length int64,
	uncompressed bool,
) *http.Response {
	return &http.Response{
		Status:           statusText,
		StatusCode:       status,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           header,
		Body:             body,
		ContentLength:    length,
		TransferEncoding: nil,
		Close:            false,
		Uncompressed:     uncompressed,
		Trailer:          nil,
		Request:          req,
		TLS:              nil,
	}
}
