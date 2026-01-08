// Package regexp selects the fastest regex engine available for a pattern.
//
// By default it compiles patterns with coregex (an accelerated RE2-compatible
// engine). When the pattern requires PCRE/Perl features that RE2/coregex
// cannot execute, the package automatically falls back to [regexp2] for full
// PCRE2 compatibility.
package regexp
