# sandboxec

`sandboxec` runs commands under a filesystem and network sandbox, through an API shaped like `os/exec`. It uses [Landlock](https://docs.kernel.org/userspace-api/landlock.html) on Linux and Seatbelt on macOS.

The sandbox restricts your process, not only the commands it starts. The first `Command` call applies the rules to the whole Go program, every goroutine included, and they stay in force until the process exits. Commands inherit them.

API reference: [go.dw1.io/x/exp/sandboxec](https://go.dw1.io/x/exp/sandboxec?godoc=1)

> [!WARNING]
> `sandboxec` is experimental, and its API can change without notice. Pin an exact version.

## Install

```sh
go get go.dw1.io/x/exp/sandboxec
```

`sandboxec` requires Go 1.25 or later, and either macOS or Linux with Landlock enabled (kernel 5.13 or later).

## Quick start

This program runs `/bin/echo` in a sandbox that grants read and execute access to `/usr` and `/bin`:

```go
package main

import (
	"fmt"
	"log"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/access"
)

func main() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
	)

	out, err := sb.Command("/bin/echo", "hello").Output()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(out))
}
```

It prints:

```text
hello
```

`echo` and the libraries it loads live under `/usr` and `/bin`, as they do on macOS and on Linux distributions with a merged `/usr`.

## How enforcement works

`New` only records rules. The first `Command` or `CommandContext` call on a `Sandboxec` enforces them on the current process, and later calls reuse that result. From then on, your process and every command it starts run under the rules, and nothing can lift them before the process exits.

If the rest of your program needs access that the commands must not have, run the commands from a separate process.

`Command` reports an invalid option or a failed enforcement in `cmd.Err`. Every `Cmd` from that `Sandboxec` carries the same error, and `Start`, `Run`, `Output`, and `CombinedOutput` fail without starting the command. After an invalid option, nothing is enforced. After a failed enforcement on Linux, some restrictions can already be in place.

```go
cmd := sb.Command("/bin/echo", "hello")
if cmd.Err != nil {
	// An option was invalid, or enforcement failed.
	log.Fatal(cmd.Err)
}
```

`Command` and `CommandContext` otherwise behave like `exec.Command` and `exec.CommandContext`, including `PATH` lookup and `exec.ErrDot`. The package also re-exports `Cmd`, `LookPath`, `ErrDot`, `ErrNotFound`, and `ErrWaitDelay` from `os/exec`. `LookPath` doesn't enforce anything.

## Filesystem rules

Filesystem access is denied by default. `WithFSRule(path, rights)` grants `rights` on `path`, and a rule for a directory covers everything beneath it.

| Rights | Allows |
| --- | --- |
| `access.FS_READ` | Reading files and listing directories |
| `access.FS_READ_EXEC` | `FS_READ`, plus running files as programs |
| `access.FS_WRITE` | Creating, changing, and removing files and directories. On Linux, also listing directories. |
| `access.FS_READ_WRITE` | `FS_READ` and `FS_WRITE` |
| `access.FS_READ_WRITE_EXEC` | `FS_READ_WRITE`, plus running files as programs |

To start a program, the rules must grant `FS_READ_EXEC` on:

- The program file.
- For a script, its interpreter, such as `/bin/sh`.
- On Linux, its dynamic loader.
- The shared libraries it loads. On Linux, `FS_READ` is enough for these.

You don't need a rule for `/dev/null`. Every sandbox allows reading and writing it, because `os/exec` opens it for each standard stream you leave `nil`.

On Linux, every rule path must exist when the sandbox is enforced, or enforcement fails. With `landlock.WithIgnoreIfMissing()`, rules skip missing paths instead.

### Host runtime access

`WithUnsafeHostRuntime()` grants `FS_READ_EXEC` on every directory in `PATH`, on the directories that its symlinked programs point into, and on the shared libraries those programs load. It saves writing rules for host tools, at the cost of a wider sandbox whose contents depend on the host. It reads `PATH` when you call `New`, and caches the libraries it finds under `os.UserCacheDir()`.

On Linux, use the option only when you trust every directory in `PATH`. To find each program's libraries, it runs the program's dynamic loader (its ELF interpreter) with `--list`, during `New` and outside the sandbox. On macOS, it reads Mach-O load commands instead.

The option skips files it can't use: scripts, missing or unreadable libraries, and dependency paths that aren't shared libraries. On Linux, it fails with `ErrInvalidOption` if it can't inspect the path of a library it found.

## Network rules

`WithNetworkRule(port, rights)` allows TCP traffic on a port, for any address:

- `access.NETWORK_BIND_TCP` allows binding a socket to the port.
- `access.NETWORK_CONNECT_TCP` allows connecting to the port.

On macOS, the sandbox blocks all network traffic that no rule allows. On Linux, it restricts only TCP, and only on ABI 4 or later:

| Traffic | Linux, ABI 4 or later | Linux, ABI 1 to 3 | macOS |
| --- | --- | --- | --- |
| TCP bind and connect | Denied, except on allowed ports | Not restricted | Denied, except on allowed ports |
| UDP, UNIX sockets, and other traffic | Not restricted | Not restricted | Denied |

On Linux, network rules need a selected ABI of 4 or later. With automatic selection on an older kernel, enforcement fails with `ErrABINotSupported`, even with `WithBestEffort`. If you pin ABI 4 or later and use `WithBestEffort`, an older kernel drops the network rules instead. To block abstract UNIX sockets on Linux, use `landlock.WithRestrictScoped()`.

## Linux

### Landlock ABI

By default, `sandboxec` uses the newest Landlock ABI that both the kernel and the package support, up to 7. `landlock.WithABI(n)` pins ABI `n` from 1 to 7, and `landlock.WithABI(0)` keeps automatic selection. A pinned ABI newer than the kernel's fails with `ErrABINotSupported`, unless you use `WithBestEffort`.

| ABI | First kernel | Adds |
| --- | --- | --- |
| 1 | 5.13 | Filesystem rules |
| 2 | 5.19 | Control over moving and linking files between directories |
| 3 | 6.2 | Control over truncating files |
| 4 | 6.7 | TCP bind and connect rules |
| 5 | 6.10 | Control over `ioctl` on device files |
| 6 | 6.12 | Scoping of abstract UNIX sockets and signals |
| 7 | 6.15 | Audit logging flags, with no new restrictions |

Treat the kernel versions as a guide and check the ABI, because distribution kernels can backport Landlock features.

### Linux-only options

The `landlock` package holds options that only Landlock supports. Code that uses them must build only for Linux, for example in a `_linux.go` file, because they exist only on Linux.

- `landlock.WithABI(n)` selects the ABI, as described in [Landlock ABI](#landlock-abi).
- `landlock.WithIgnoreIfMissing()` makes rules skip paths that don't exist.
- `landlock.WithRestrictScoped()` keeps the process from connecting to abstract UNIX sockets or sending signals outside its sandbox. It needs ABI 6 or later.

```go
sb := sandboxec.New(
	landlock.WithIgnoreIfMissing(),
	landlock.WithRestrictScoped(),
	sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
)
```

### Enforcement details

- Enforcement sets `no_new_privs` on the process, so setuid and file-capability programs, such as `sudo`, don't gain privileges when the process or its commands run them.
- Each `Sandboxec` adds its restrictions on top of those already in place, and access then needs every set of rules to allow it. A second `Sandboxec` can only narrow access.
- A `Sandboxec` with no rules restricts everything its ABI supports apart from `/dev/null`, including abstract UNIX sockets and signals on ABI 6 or later.
- Landlock can't restrict some file operations, including `stat`, `chdir`, `chmod`, and `chown`. The [kernel documentation](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags) has the full list.

## macOS

`sandboxec` turns your rules into a Seatbelt policy and applies it with `sandbox_init`. The policy denies file access, program execution, and network traffic unless a rule allows them, and allows every other operation.

- A process holds one Seatbelt policy. After one `Sandboxec` enforces its rules, another with different rules fails with `ErrSeatbeltUnavailable`. With `WithBestEffort`, that second `Sandboxec` runs its commands under the first policy instead. A `Sandboxec` with identical rules succeeds, because its policy is already in place.
- `sandboxec` resolves symlinks in rule paths, because Seatbelt matches resolved paths (for example, `/tmp` is `/private/tmp`). It also makes the metadata of each symlink on the way readable, so commands can still use the original path.
- Reading file metadata outside the rules is denied, unlike on Linux.
- The policy allows reading the root directory entry (`/`) itself, which dyld needs to start any process.
- A rule for a missing path doesn't cause an error.

## Best-effort mode

`WithBestEffort()` ignores some enforcement failures, so commands can run with partial enforcement or none. Don't treat it as a security boundary.

- On Linux, a missing Landlock or a pinned ABI newer than the kernel's doesn't fail enforcement. Landlock enforces what the kernel supports. Options that need a newer ABI than the selected one still fail, as [Errors](#errors) describes.
- On macOS, a failed `sandbox_init` doesn't fail enforcement. Commands run under the process's existing policy, if it has one.

## Errors

Match these errors with `errors.Is`:

| Error | Meaning |
| --- | --- |
| `ErrUnavailable` | The platform sandbox is unavailable or failed to start. `ErrLandlockUnavailable` and `ErrSeatbeltUnavailable` both match it. |
| `ErrLandlockUnavailable` | Linux: the kernel doesn't support Landlock, or `sandboxec` can't query it. |
| `ErrSeatbeltUnavailable` | macOS: Seatbelt couldn't be initialized, including when the process already holds a different policy. |
| `ErrABINotSupported` | Linux: the pinned ABI is newer than the kernel's, or an option needs a newer ABI than the selected one. Network rules need ABI 4 and `landlock.WithRestrictScoped()` needs ABI 6. `WithBestEffort` ignores only the first case. |
| `ErrInvalidOption` | An option is malformed: an empty path, zero rights, or an ABI outside 0 to 7. On Linux, also a library that `WithUnsafeHostRuntime` can't inspect. |

Other failures, such as a missing rule path on Linux, return the underlying error.

## License

Apache License 2.0. See [LICENSE](LICENSE).
