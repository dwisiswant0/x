# sandboxec

Sandboxec provides an os/exec-like API backed by Linux Landlock. It restricts the current process and all goroutines, then runs commands using exec.Cmd.

## Quick start

```go
sb := sandboxec.New(
    sandboxec.WithABI(6),
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
    sandboxec.WithABI(6),
    sandboxec.WithNetworkRule(8080, access.NETWORK_BIND_TCP),
    sandboxec.WithNetworkRule(53, access.NETWORK_CONNECT_TCP),
)
cmd := sb.Command("/bin/true")
_ = cmd.Run()
```

## Best-effort mode

`sandboxec.WithBestEffort()` allows your program to run on kernels with older or missing Landlock support. In best-effort mode, enforcement may be partial or absent, so treat it as a compatibility fallback rather than a security boundary.

## Network policy semantics

- On Landlock ABI V4+, network access is restricted with a deny-by-default model.
- `WithNetworkRule` explicitly allowlists TCP `bind(2)` / `connect(2)` access for selected ports.
- If you set no network rules on ABI V4+, TCP bind/connect are denied.
- On ABI V1-V3, Landlock does not provide TCP bind/connect restrictions.
- In best-effort mode, kernel limitations may relax or disable enforcement.

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
| ABI | 1-6 (selected with WithABI) |

### Kernel capability guide

| Capability | Landlock ABI | Typical minimum kernel |
| --- | --- | --- |
| Filesystem restrictions | V1+ | 5.13+ |
| TCP bind/connect restrictions | V4+ | 6.7+ |
| Scoped IPC restrictions | V6+ | newer kernels only |

## Notes

- `sandboxec.Command` and `sandboxec.CommandContext` mirror `exec.Command` behavior.
- Path lookup and `exec.ErrDot` behavior are preserved.
- Use `WithIgnoreIfMissing` to gracefully allow optional paths.
- Without `WithBestEffort`, unsupported requested ABI fails closed with an error.

## Filesystem options

- `WithFSRule` adds a filesystem rule for a path using `access.FS` helper masks.
- `WithNetworkRule` adds a network rule for a port using `access.Network` masks.
- `WithUnsafeHostRuntime` allowlists host runtime paths (PATH, LD_LIBRARY_PATH, and discovered shared-library directories) with `FS_READ_EXEC`; this is host-dependent and less strict than explicit rules.

