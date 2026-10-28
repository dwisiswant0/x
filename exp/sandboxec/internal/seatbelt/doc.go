// nolint
//go:build darwin
// +build darwin

// Package seatbelt builds macOS Seatbelt policies and applies them to the
// current process with sandbox_init.
//
// Policies are written in SBPL, Seatbelt's Scheme-like policy language, which
// Apple does not publicly document. This package owns its syntax and quoting;
// the sandboxec package decides which rules a sandbox needs.
package seatbelt
