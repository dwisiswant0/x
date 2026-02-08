# x

A collection of Go hacks maintained by [**@dwisiswant0**](https://github.com/dwisiswant0).

## Catalogs

- [cast](cast): functions to convert between different types.
- [exp](exp): contains experimental and/or unstable APIs.
	- [exp/file](exp/file): an `os.File`-compatible API that prefers memory-mapped.
	- [exp/gctuner](exp/gctuner): a lightweight GC tuning helper based on a heap.
	- [exp/os/sandboxec](exp/os/sandboxec): wraps os/exec with Landlock policy enforcement.
- [hash/wyhash](hash/wyhash): a Go implementation of the wyhash non-cryptographic.
- [json](json): fast JSON encoding and decoding functionality.
- [regexp](regexp): selects the fastest regex engine available for a pattern.

## Install

> [!NOTE]
> Requires [**Go 1.25+**](https://go.dev/doc/install).
> The packages in this repo use subdirectory module resolution introduced in Go 1.25, as this is a monorepo.

```sh
go get go.dw1.io/x/<package>
```

> [!WARNING]
> **`x/exp`** contains experimental and/or unstable APIs. Expect breaking changes; pin exact versions when consuming it.

## Versioning

Each package is versioned independently. Tags follow the format:

```
<package>/v<major>.<minor>.<patch>
```

## License

Apache License 2.0.
