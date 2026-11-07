package bump

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/mod/semver"
	"golang.org/x/vuln/scan"

	"go.dw1.io/x/vuln/internal/govulncheck"
	"go.dw1.io/x/vuln/internal/osv"
)

// errProtocol reports scanner output that the copied message types can't
// decode, which happens when golang.org/x/vuln is upgraded without copying
// them again (see README.md).
var errProtocol = errors.New("unsupported govulncheck output")

// scanResult is the decoded output of one govulncheck scan.
type scanResult struct {
	osvs     map[string]*osv.Entry // by advisory ID
	findings []*govulncheck.Finding
}

// scanModule runs govulncheck in-process on the module in the working
// directory and decodes its JSON output.
func scanModule(ctx context.Context, opts *Options, stderr io.Writer) (*scanResult, error) {
	args := []string{"-format", "json", "-scan", string(opts.Level)}
	if opts.DB != "" {
		args = append(args, "-db", opts.DB)
	}

	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}

	if opts.Test {
		args = append(args, "-test")
	}

	args = append(args, opts.Patterns...)

	var out bytes.Buffer

	cmd := scan.Command(ctx, args...)
	cmd.Stdout = &out
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("scanning: %w", err)
	}
	// In JSON mode the scanner exits 0 even when it finds vulnerabilities,
	// so any error here is a failure to scan. The scanner's errors already
	// start with "govulncheck: ".
	if err := cmd.Wait(); err != nil {
		return nil, err //nolint:wrapcheck // the scanner prefixes its errors
	}

	return decodeScan(&out)
}

// decodeScan decodes a stream of govulncheck JSON messages. The stream must
// start with a config message whose protocol has the major version of the
// copied message types.
func decodeScan(r io.Reader) (*scanResult, error) {
	dec := json.NewDecoder(r)

	var first govulncheck.Message
	if err := dec.Decode(&first); err != nil && err != io.EOF {
		return nil, fmt.Errorf("decoding govulncheck output: %w", err)
	}

	if err := checkProtocol(first.Config); err != nil {
		return nil, err
	}

	res := &scanResult{osvs: map[string]*osv.Entry{}}

	for {
		var msg govulncheck.Message

		err := dec.Decode(&msg)
		if err == io.EOF {
			return res, nil
		}

		if err != nil {
			return nil, fmt.Errorf("decoding govulncheck output: %w", err)
		}

		switch {
		case msg.OSV != nil:
			res.osvs[msg.OSV.ID] = msg.OSV
		case msg.Finding != nil:
			res.findings = append(res.findings, msg.Finding)
		}
	}
}

// checkProtocol checks the scanner's config message, which comes first.
func checkProtocol(cfg *govulncheck.Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: no config message", errProtocol)
	}

	if semver.Major(cfg.ProtocolVersion) != semver.Major(govulncheck.ProtocolVersion) {
		return fmt.Errorf("%w: protocol %s, want %s", errProtocol, cfg.ProtocolVersion, govulncheck.ProtocolVersion)
	}

	return nil
}
