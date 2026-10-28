// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

func (s *Sandboxec) enforce() error {
	policy := seatbeltPolicy(&s.cfg)

	if err := applySeatbelt(policy, 0); err != nil {
		if s.cfg.BestEffort {
			return nil
		}

		return err
	}

	return nil
}

func seatbeltPolicy(cfg *config.Config) string {
	// The filesystem is deny-by-default, as on Linux; only FS rules open it.
	lines := []string{
		"(version 1)",
		"(allow default)",
		"(deny file-read*)",
		"(deny file-write*)",
		"(deny file-map-executable)",
		"(deny process-exec*)",
		// dyld reads the root directory to locate its shared cache; without
		// this, every exec aborts with SIGABRT before reaching main.
		`(allow file-read-data (literal "/"))`,
	}

	for _, rule := range cfg.FSRules {
		path, links := resolveSeatbeltPath(filepath.Clean(rule.Path))

		// Seatbelt checks each symlink a command traverses, so reaching the
		// rule through its original path needs each link's metadata readable.
		for _, link := range links {
			lines = append(lines, `(allow file-read-metadata (literal `+seatbeltQuote(link)+`))`)
		}

		quotedPath := seatbeltQuote(path)

		if rule.Rights&access.FS_READ != 0 {
			lines = append(lines, `(allow file-read* (subpath `+quotedPath+`))`)
		}

		if rule.Rights&access.FS_WRITE != 0 {
			lines = append(lines, `(allow file-write* (subpath `+quotedPath+`))`)
		}

		// Like Landlock's execute right, exec rights let the rule's files run
		// as programs; process-exec* also covers a script's interpreter.
		if rule.Rights&access.FS_READ_EXEC == access.FS_READ_EXEC {
			lines = append(lines,
				`(allow file-map-executable (subpath `+quotedPath+`))`,
				`(allow process-exec* (subpath `+quotedPath+`))`,
			)
		}
	}

	allowInbound := false
	allowOutbound := false
	inboundPorts := make([]uint16, 0)
	outboundPorts := make([]uint16, 0)
	seenInbound := make(map[uint16]struct{})
	seenOutbound := make(map[uint16]struct{})

	for _, rule := range cfg.NetRules {
		if rule.Rights&access.NETWORK_BIND_TCP != 0 {
			allowInbound = true
			if _, ok := seenInbound[rule.Port]; !ok {
				seenInbound[rule.Port] = struct{}{}
				inboundPorts = append(inboundPorts, rule.Port)
			}
		}

		if rule.Rights&access.NETWORK_CONNECT_TCP != 0 {
			allowOutbound = true
			if _, ok := seenOutbound[rule.Port]; !ok {
				seenOutbound[rule.Port] = struct{}{}
				outboundPorts = append(outboundPorts, rule.Port)
			}
		}
	}

	lines = append(lines, "(deny network-inbound)", "(deny network-outbound)")

	if allowInbound {
		for _, port := range inboundPorts {
			lines = append(lines, `(allow network-inbound (local tcp "*:`+fmt.Sprintf("%d", port)+`"))`)
		}
	}

	if allowOutbound {
		for _, port := range outboundPorts {
			lines = append(lines, `(allow network-outbound (remote tcp "*:`+fmt.Sprintf("%d", port)+`"))`)
		}
	}

	return strings.Join(lines, "\n")
}

var seatbeltEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// seatbeltQuote returns s as an SBPL string literal. Resolved paths include
// symlink targets read from disk, so they must not be able to end the string.
func seatbeltQuote(s string) string {
	return `"` + seatbeltEscaper.Replace(s) + `"`
}

// maxSymlinkHops bounds symlink resolution, matching [filepath.EvalSymlinks].
const maxSymlinkHops = 255

// resolveSeatbeltPath returns the symlink-free form of path, which is what
// Seatbelt matches against (for example, /tmp is /private/tmp), and the
// symlink-free location of each symlink traversed to reach it. Relative or
// unresolvable paths are returned unchanged, with no links.
func resolveSeatbeltPath(path string) (string, []string) {
	if !filepath.IsAbs(path) {
		return path, nil
	}

	var links []string
	resolved := "/"
	pending := strings.Split(path, "/")
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		if name == "" || name == "." {
			continue
		}

		next := filepath.Join(resolved, name)
		info, err := os.Lstat(next)
		if err != nil {
			return path, nil
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}

		target, err := os.Readlink(next)
		if err != nil || len(links) == maxSymlinkHops {
			return path, nil
		}
		links = append(links, next)
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}

	return resolved, links
}
