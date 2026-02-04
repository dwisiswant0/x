# gctuner

Lightweight GC tuning for Go.

Adjusts Go GC dynamically to keep GC triggering near a fixed heap threshold to help keep usage under control.

## Install

```bash
go get -u go.dw1.io/x/exp/gctuner@latest
```

## How it works

```text
 _______________  => limit: host/cgroup memory hard limit
|               |
|---------------| => threshold: increase GCPercent when gc_trigger < threshold
|               |
|---------------| => gc_trigger: heap_live + heap_live * GCPercent / 100
|               |
|---------------|
|   heap_live   |
|_______________|

threshold = inuse + inuse * (gcPercent / 100)
=> gcPercent = (threshold - inuse) / inuse * 100

if threshold < 2*inuse, so gcPercent < 100, and GC positively to avoid OOM
if threshold > 2*inuse, so gcPercent > 100, and GC negatively to reduce GC times
```

In short: the tuner continuously recomputes Go GC to keep the GC trigger near
the threshold while respecting min/max bounds.

## Terminology

- **heap_live / inuse**: current live heap size.
- **gc_trigger**: the heap size at which the runtime triggers GC.
- **threshold**: the target heap size used to derive Go GC.

## Usage

1. **Enable with options**

```go
package main

import "go.dw1.io/x/exp/gctuner"

func main() {
	// Use a threshold at 70% of effective memory limit and cap GOGC bounds.
	gctuner.MustEnable(
		int64(gctuner.GetMemLimitPercent(70)),
		gctuner.WithMinGCPercent(50),
		gctuner.WithMaxGCPercent(500),
	)
}
```

The recommended threshold is 70% of the effective memory limit. See “[How we saved 70K cores across 30 Mission-Critical services (Large-Scale, Semi-Automated Go GC Tuning @Uber) | Uber Blog,](https://www.uber.com/en-ID/blog/how-we-saved-70k-cores-across-30-mission-critical-services/)” Uber Blog, Dec. 22, 2021.

2. **Explicit memory limit override**

```go
package main

import "go.dw1.io/x/exp/gctuner"

func main() {
	// Set a memory limit override, then use -1 to derive the threshold from
	// the effective memory limit.
	gctuner.SetMemLimitPercent(80)
	gctuner.MustEnable(-1)
}
```

3. **Auto-enable on import**

```go
package main

import _ "go.dw1.io/x/exp/gctuner/auto"

func main() {
	// gctuner is enabled during init with default limits.
}
```

The `auto` package configures a memory limit and starts the tuner during init.
Use it only when those defaults are acceptable for the process.

## Behavior summary

- **GOGC**: Always dynamically tuned to hit the heap threshold.
- **Effective memory limit for `GetMemLimitPercent`**:
	- Go <1.19: detected host/cgroup memory
	- Go ≥1.19: `GOMEMLIMIT` (if set) overrides detected host/cgroup memory
- **Go ≥1.19 memory limit set by the tuner** (per GC):
	1) explicit `SetMemLimitPercent`
	2) `GOMEMLIMIT` if set
	3) the threshold

## Config details

### Threshold resolution

- `0` disables the tuner.
- `-1` derives the threshold from the effective memory limit.
- `n > 0` uses `n` bytes as the threshold.

If threshold is `-1` and the effective limit cannot be determined, `Enable` returns an error.

### GC percent bounds

Adjust the GC percent bounds with `WithMinGCPercent` and `WithMaxGCPercent` to control how aggressively the tuner adjusts Go GC. The default bounds are `50` and `500`. `Enable` returns an
error if the bounds are invalid or inverted.

## Op notes

- The tuner runs as a single global instance per process.
- Setting `SetMemLimitPercent(0)` clears the override.
- On non-Linux platforms, cgroup-based limit detection returns `0`.
- When the heap exceeds the threshold, the tuner clamps to the minimum Go GC to increase GC frequency and reduce memory growth.

> [!NOTE]
> - This package intentionally avoids external dependencies to keep overhead low.
> - It is safe to call `Enable` multiple times; later calls update the threshold and bounds of the existing tuner.

## License

This package is a fork of `github.com/bytedance/gopkg/util/gctuner` and is released under the Apache-2.0 license.
