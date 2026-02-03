// Package gctuner provides a lightweight GC tuning helper based on a heap
// threshold. It dynamically adjusts GC settings so the GC trigger stays close
// to a target heap usage (the “threshold”).
//
// # Overview
//
// The Go runtime triggers a GC cycle when the live heap reaches
//
//	gc_trigger = heap_live + heap_live * GCPercent / 100
//
// gctuner solves for GCPercent at runtime so the trigger remains near a chosen
// threshold, within configured min/max bounds. This gives a simple operational
// model: “keep the live heap below X bytes.”
//
// # Threshold selection
//
// A threshold can be set explicitly (bytes), or derived from the effective
// memory limit via [Enable](-1). A common choice is 70% of the effective memory
// limit. The effective memory limit is determined as follows:
//
//	Go < 1.19: detected host/cgroup memory limit
//	Go >= 1.19: GOMEMLIMIT (if set) overrides host/cgroup detection
//
// On Linux, memory limit detection is cgroup-aware. On non-Linux platforms
// it returns 0 (unknown).
//
// Memory limits on Go 1.19+
//
// When [SetMemLimitPercent] is used, gctuner also sets a Go runtime memory limit
// with [debug.SetMemoryLimit]. The precedence is:
//
//  1. [SetMemLimitPercent] override
//  2. GOMEMLIMIT (if set)
//  3. threshold
//
// # Disabling
//
// [Enable](0) disables the tuner. [Enable](-1) derives the threshold from the
// effective memory limit (or [SetMemLimitPercent] override if present). If the
// limit cannot be determined, [Enable](-1) returns an error.
package gctuner
