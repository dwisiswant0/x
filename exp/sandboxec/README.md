# sandboxec

Sandboxec provides an os/exec-like API backed by Linux Landlock and macOS Seatbelt. It restricts the current process and all goroutines, then runs commands using exec.Cmd.

## macOS Seatbelt (Darwin)

On Darwin, filesystem/network options are translated into a Seatbelt policy and applied via `sandbox_init`.

Darwin currently supports:

- `WithBestEffort`
- `WithFSRule`
- `WithNetworkRule`
- `WithUnsafeHostRuntime`

The options in the `landlock` package are Linux-only and do not exist on Darwin.

As on Linux, running a file as a program requires `FS_READ_EXEC` or `FS_READ_WRITE_EXEC` on its path, and for a script, on its interpreter too.

When filesystem access is restricted, the policy also allows reading the root directory entry (`/`) itself, which dyld needs to start any process. Rule paths are resolved through symlinks, because Seatbelt matches resolved paths (for example, `/tmp` is `/private/tmp`), and the metadata of each symlink traversed to reach them is made readable so commands can still use the original path.

```go
sb := sandboxec.New(
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
)

cmd := sb.Command("/bin/echo", "hello")
_ = cmd.Run()
```

## Quick start

```go
sb := sandboxec.New(
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
)

cmd := sb.Command("/bin/echo", "hello")
out, err := cmd.Output()
```

## Examples

Filesystem restrictions (read /usr and /bin, write /tmp):

```go
sb := sandboxec.New(
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
)
cmd := sb.Command("/bin/ls", "-l")
_ = cmd.Run()
```

Network restrictions (bind to 8080 and connect to 53 only):

```go
sb := sandboxec.New(
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
    sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
    sandboxec.WithNetworkRule(8080, access.NETWORK_BIND_TCP),
    sandboxec.WithNetworkRule(53, access.NETWORK_CONNECT_TCP),
)
cmd := sb.Command("/bin/true")
_ = cmd.Run()
```

## Best-effort mode

`sandboxec.WithBestEffort()` lets programs run on systems with older kernels or missing Landlock support. In this mode, enforcement can be partial or skipped, so do not treat it as a security boundary.

## Filesystem policy semantics

- Filesystem access is deny-by-default on Linux and Darwin. Only `WithFSRule` and `WithUnsafeHostRuntime` grant it.
- A sandbox without filesystem rules, including one with only network rules or scoped IPC restrictions, gets no filesystem access rights: its commands cannot read or write files or run programs. Operations that the platform sandbox does not control, such as reading file metadata on Linux, are not affected.

## Network policy semantics

- On Landlock ABI V4+, network access is deny-by-default.
- `WithNetworkRule` allows TCP `bind(2)` and `connect(2)` on selected ports.
- With no network rules on ABI V4+, TCP bind/connect calls are denied.
- On Darwin, Seatbelt network policy is also deny-by-default, and `WithNetworkRule` opens selected ports.
- On ABI V1-V3, Landlock does not restrict TCP bind/connect.
- In best-effort mode, enforcement can be relaxed or skipped.

## Landlock limitations and requirements

- Landlock is Linux-only and requires kernel support.
- Once enforced, Landlock restrictions apply to the current process and cannot be removed.
- Some filesystem operations cannot be restricted yet (see kernel documentation).
- Scoped IPC restrictions are available starting at ABI V6.

## Compatibility matrix

| Component | Supported |
| --- | --- |
| Go | 1.24+ |
| Kernel | 5.13+ for Landlock V1, newer for higher ABIs |
| ABI | 1-7 (`landlock.WithABI(0)` auto-selects highest supported ABI) |

### Kernel capability guide

| Capability | Landlock ABI | Typical minimum kernel |
| --- | --- | --- |
| Filesystem restrictions | V1+ | 5.13+ |
| TCP bind/connect restrictions | V4+ | 6.7+ |
| Scoped IPC restrictions | V6+ | newer kernels only |

## Notes

- `sandboxec.Command` and `sandboxec.CommandContext` mirror `exec.Command` behavior.
- Path lookup and `exec.ErrDot` behavior are preserved.
- Linux defaults to the highest available ABI supported by both kernel and package.
- `landlock.WithABI(0)` forces auto-selection; explicit `landlock.WithABI(1..7)` pins the ABI.
- Use `landlock.WithIgnoreIfMissing` to gracefully allow optional paths.
- Without `WithBestEffort`, unsupported requested ABI values return an error.

## Options

- `WithFSRule` adds a filesystem rule for a path using `access.FS` masks.
- `WithNetworkRule` adds a network rule for a port using `access.Network` masks.
- `WithUnsafeHostRuntime` adds `FS_READ_EXEC` rules for runtime paths discovered from `PATH` and dynamic-linker dependency files. This behavior depends on the host and is less strict than explicit rules.

Dependency discovery details:

- Linux: dependency files are resolved via linker/runtime inspection (`ldd`-style expansion).
- Darwin: dependency files are resolved from Mach-O load commands.

Linux-only options are in the `landlock` package. They exist only on Linux, so code that uses them must be built for Linux only:

- `landlock.WithABI` selects the Landlock ABI.
- `landlock.WithIgnoreIfMissing` ignores rule paths that do not exist.
- `landlock.WithRestrictScoped` enables scoped IPC restrictions (ABI V6+).

```go
sb := sandboxec.New(
    landlock.WithABI(7),
    landlock.WithRestrictScoped(),
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
)
```

## Errors

- `errors.Is(err, sandboxec.ErrUnavailable)` reports that the platform sandbox is unavailable, on any platform. `ErrLandlockUnavailable` and `ErrSeatbeltUnavailable` both match it.
- `ErrABINotSupported` reports a Landlock ABI that the kernel or the other options do not support.
- `ErrInvalidOption` reports a malformed option, or one that could not be applied, such as `WithUnsafeHostRuntime` on Linux when the path of a library it found cannot be inspected.
