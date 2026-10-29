// nolint
//go:build darwin
// +build darwin

package seatbelt

import (
	"strconv"
	"strings"
)

// Operation names a Seatbelt operation. A name ending in "*" covers every
// operation whose name starts with the rest of it.
//
// Rule.String writes an Operation into the policy unquoted, so it must be
// one of the constants below, never a value from input.
type Operation string

// Operations that sandboxec policies use.
const (
	// Default sets the action for operations that no other rule matches.
	Default           Operation = "default"
	FileRead          Operation = "file-read*"
	FileReadData      Operation = "file-read-data"
	FileReadMetadata  Operation = "file-read-metadata"
	FileWrite         Operation = "file-write*"
	FileWriteData     Operation = "file-write-data"
	FileMapExecutable Operation = "file-map-executable"
	ProcessExec       Operation = "process-exec*"
	NetworkInbound    Operation = "network-inbound"
	NetworkOutbound   Operation = "network-outbound"
)

// Filter limits a rule to the resources it matches.
type Filter struct {
	// name is the SBPL filter, with any arguments that precede the quoted
	// value, such as "subpath" or "local tcp".
	name  string
	value string
}

// All matches every resource. A rule with it applies to the whole operation.
var All Filter

// Literal matches path exactly.
func Literal(path string) Filter {
	return Filter{name: "literal", value: path}
}

// Subpath matches path and everything under it.
func Subpath(path string) Filter {
	return Filter{name: "subpath", value: path}
}

// LocalTCP matches TCP sockets whose local port is port, on any address.
func LocalTCP(port uint16) Filter {
	return Filter{name: "local tcp", value: "*:" + strconv.Itoa(int(port))}
}

// RemoteTCP matches TCP sockets whose remote port is port, on any host.
func RemoteTCP(port uint16) Filter {
	return Filter{name: "remote tcp", value: "*:" + strconv.Itoa(int(port))}
}

// Rule allows or denies an operation on the resources its filter matches.
type Rule struct {
	allow     bool
	operation Operation
	filter    Filter
}

// Allow returns a rule that allows op on the resources that filter matches.
func Allow(op Operation, filter Filter) Rule {
	return Rule{allow: true, operation: op, filter: filter}
}

// Deny returns a rule that denies op on the resources that filter matches.
func Deny(op Operation, filter Filter) Rule {
	return Rule{operation: op, filter: filter}
}

// String returns the rule in SBPL.
func (r Rule) String() string {
	action := "deny"
	if r.allow {
		action = "allow"
	}

	if r.filter == (Filter{}) {
		return "(" + action + " " + string(r.operation) + ")"
	}

	return "(" + action + " " + string(r.operation) + " (" + r.filter.name + " " + quote(r.filter.value) + "))"
}

// Policy is a Seatbelt policy.
//
// When several rules match a request, a rule on an exact operation, such as
// file-read-data, takes precedence over one on a "*" operation that covers it,
// such as file-read*, wherever each appears. Among rules on the same
// operation, the last one decides.
type Policy []Rule

// String returns the policy in SBPL.
func (p Policy) String() string {
	lines := make([]string, 0, 1+len(p))
	lines = append(lines, "(version 1)")
	for _, rule := range p {
		lines = append(lines, rule.String())
	}

	return strings.Join(lines, "\n")
}

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// quote returns s as an SBPL string literal. Paths can come from symlink
// targets on disk, so they must not be able to end the string.
func quote(s string) string {
	return `"` + escaper.Replace(s) + `"`
}
