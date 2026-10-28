// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
	"go.dw1.io/x/exp/sandboxec/internal/seatbelt"
)

func (s *Sandboxec) enforce() error {
	if err := applySeatbelt(seatbeltPolicy(&s.cfg)); err != nil {
		if s.cfg.BestEffort {
			return nil
		}

		return err
	}

	return nil
}

// applySeatbelt sandboxes the current process with policy and reports any
// failure as ErrSeatbeltUnavailable.
func applySeatbelt(policy seatbelt.Policy) error {
	if err := seatbelt.Apply(policy); err != nil {
		return fmt.Errorf("%w: %v", ErrSeatbeltUnavailable, err)
	}

	return nil
}

func seatbeltPolicy(cfg *config.Config) seatbelt.Policy {
	// The filesystem is deny-by-default, as on Linux; only FS rules open it.
	// Each allow that follows overrides these denials: it either comes later
	// on the same operation or names a more exact one, such as
	// file-read-data under file-read*.
	policy := seatbelt.Policy{
		seatbelt.Allow(seatbelt.Default, seatbelt.All),
		seatbelt.Deny(seatbelt.FileRead, seatbelt.All),
		seatbelt.Deny(seatbelt.FileWrite, seatbelt.All),
		seatbelt.Deny(seatbelt.FileMapExecutable, seatbelt.All),
		seatbelt.Deny(seatbelt.ProcessExec, seatbelt.All),
		// dyld reads the root directory to locate its shared cache; without
		// this, every exec aborts with SIGABRT before reaching main.
		seatbelt.Allow(seatbelt.FileReadData, seatbelt.Literal("/")),
	}

	for _, rule := range cfg.FSRules {
		path, links := resolveSeatbeltPath(rule.Path)

		// Seatbelt checks each symlink a command traverses, so reaching the
		// rule through its original path needs each link's metadata readable.
		for _, link := range links {
			policy = append(policy, seatbelt.Allow(seatbelt.FileReadMetadata, seatbelt.Literal(link)))
		}

		subtree := seatbelt.Subpath(path)

		if rule.Rights&access.FS_READ != 0 {
			policy = append(policy, seatbelt.Allow(seatbelt.FileRead, subtree))
		}

		if rule.Rights&access.FS_WRITE != 0 {
			policy = append(policy, seatbelt.Allow(seatbelt.FileWrite, subtree))
		}

		// Like Landlock's execute right, exec rights let the rule's files run
		// as programs; process-exec* also covers a script's interpreter.
		if rule.Rights&access.FS_READ_EXEC == access.FS_READ_EXEC {
			policy = append(policy,
				seatbelt.Allow(seatbelt.FileMapExecutable, subtree),
				seatbelt.Allow(seatbelt.ProcessExec, subtree),
			)
		}
	}

	var inboundPorts, outboundPorts []uint16
	seenInbound := make(map[uint16]struct{})
	seenOutbound := make(map[uint16]struct{})

	for _, rule := range cfg.NetRules {
		if rule.Rights&access.NETWORK_BIND_TCP != 0 {
			if _, ok := seenInbound[rule.Port]; !ok {
				seenInbound[rule.Port] = struct{}{}
				inboundPorts = append(inboundPorts, rule.Port)
			}
		}

		if rule.Rights&access.NETWORK_CONNECT_TCP != 0 {
			if _, ok := seenOutbound[rule.Port]; !ok {
				seenOutbound[rule.Port] = struct{}{}
				outboundPorts = append(outboundPorts, rule.Port)
			}
		}
	}

	policy = append(policy,
		seatbelt.Deny(seatbelt.NetworkInbound, seatbelt.All),
		seatbelt.Deny(seatbelt.NetworkOutbound, seatbelt.All),
	)

	for _, port := range inboundPorts {
		policy = append(policy, seatbelt.Allow(seatbelt.NetworkInbound, seatbelt.LocalTCP(port)))
	}

	for _, port := range outboundPorts {
		policy = append(policy, seatbelt.Allow(seatbelt.NetworkOutbound, seatbelt.RemoteTCP(port)))
	}

	return policy
}

// maxSymlinkHops bounds symlink resolution, matching the kernel's MAXSYMLINKS.
const maxSymlinkHops = 32

// resolveSeatbeltPath returns the symlink-free form of path, which is what
// Seatbelt matches against (for example, /tmp is /private/tmp), and the
// symlink-free location of each symlink traversed to reach it. Relative or
// unresolvable paths are returned as [unresolvedSeatbeltPath] gives them, with
// no links.
//
// Like the kernel, it applies each ".." to the directory that the components
// before it lead to, so path must not be cleaned first: cleaning turns
// "link/.." into the directory holding the symlink rather than the parent of
// its target.
func resolveSeatbeltPath(path string) (string, []string) {
	if !filepath.IsAbs(path) {
		return unresolvedSeatbeltPath(path), nil
	}

	var links []string
	resolved := "/"
	resolvedIsDir := true
	pending := strings.Split(path, "/")
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		if name == "" || name == "." {
			continue
		}

		// The kernel fails a name or ".." after a file with ENOTDIR.
		if !resolvedIsDir {
			return unresolvedSeatbeltPath(path), nil
		}

		next := filepath.Join(resolved, name)
		info, err := os.Lstat(next)
		if err != nil {
			return unresolvedSeatbeltPath(path), nil
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			resolvedIsDir = info.IsDir()
			continue
		}

		target, err := os.Readlink(next)
		if err != nil || len(links) == maxSymlinkHops {
			return unresolvedSeatbeltPath(path), nil
		}
		links = append(links, next)
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}

	return resolved, links
}

// unresolvedSeatbeltPath returns path for a policy rule when the path cannot be
// resolved. Without "..", cleaning it changes nothing the kernel would see. With
// "..", the cleaned form can name a directory the kernel would never reach
// through path, so path is kept as is, which Seatbelt never matches.
func unresolvedSeatbeltPath(path string) string {
	if slices.Contains(strings.Split(path, "/"), "..") {
		return path
	}

	return filepath.Clean(path)
}
