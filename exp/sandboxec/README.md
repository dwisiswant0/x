# sandboxec

Sandboxec provides an os/exec-like API backed by Linux Landlock and macOS Seatbelt. It restricts the current process and all goroutines, then runs commands using exec.Cmd.

## macOS Seatbelt (Darwin)

On Darwin, filesystem/network options are translated into a Seatbelt policy and applied via `sandbox_init`. Build with `CGO_ENABLED=0` (required by goffi).

Darwin currently supports:

- `WithBestEffort`
- `WithFSRule`
- `WithNetworkRule`
- `WithUnsafeHostRuntime`

Darwin currently does not support `WithABI`, `WithIgnoreIfMissing`, or `WithRestrictScoped`.

```go
sb := sandboxec.New(
    sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
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
    sandboxec.WithABI(7),
    sandboxec.WithNetworkRule(8080, access.NETWORK_BIND_TCP),
    sandboxec.WithNetworkRule(53, access.NETWORK_CONNECT_TCP),
)
cmd := sb.Command("/bin/true")
_ = cmd.Run()
```

## Best-effort mode

`sandboxec.WithBestEffort()` lets programs run on systems with older kernels or missing Landlock support. In this mode, enforcement can be partial or skipped, so do not treat it as a security boundary.

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
| ABI | 1-7 (`WithABI(0)` auto-selects highest supported ABI) |

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
- `WithABI(0)` forces auto-selection; explicit `WithABI(1..7)` pins the ABI.
- Use `WithIgnoreIfMissing` to gracefully allow optional paths.
- Without `WithBestEffort`, unsupported requested ABI values return an error.

## Options

- `WithFSRule` adds a filesystem rule for a path using `access.FS` masks.
- `WithNetworkRule` adds a network rule for a port using `access.Network` masks.
- `WithUnsafeHostRuntime` adds `FS_READ_EXEC` rules for runtime paths discovered from `PATH` and dynamic-linker dependency files. This behavior depends on the host and is less strict than explicit rules.

Dependency discovery details:

- Linux: dependency files are resolved via linker/runtime inspection (`ldd`-style expansion).
- Darwin: dependency files are resolved from Mach-O load commands.

