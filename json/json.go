//go:build (linux || darwin || windows) && (amd64 || arm64)

package json

import (
	"io"

	"github.com/bytedance/sonic"
)

var api = sonic.ConfigStd

// Marshal encodes a Go value as JSON using the current API config.
func Marshal(v any) ([]byte, error) {
	return api.Marshal(v)
}

// Unmarshal decodes a JSON payload into the provided destination using the current API config.
func Unmarshal(data []byte, v any) error {
	return api.Unmarshal(data, v)
}

// MarshalIndent encodes a Go value as indented JSON using the current API config.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return api.MarshalIndent(v, prefix, indent)
}

// NewDecoder creates a streaming decoder using the current API config.
func NewDecoder(r io.Reader) Decoder {
	return api.NewDecoder(r)
}

// NewEncoder creates a streaming encoder using the current API config.
func NewEncoder(w io.Writer) Encoder {
	return api.NewEncoder(w)
}

// Encoder is a JSON encoder.
type Encoder = sonic.Encoder

// Decoder is a JSON decoder.
type Decoder = sonic.Decoder

// SetConfig sets the configuration for the JSON package.
func SetConfig(config *sonic.Config) {
	api = config.Froze()
}
