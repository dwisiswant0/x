# x

A collection of Go hacks maintained by [**@dwisiswant0**](https://github.com/dwisiswant0).

## Catalogs

- [cast](cast): functions to convert between different types. [docs](https://go.dw1.io/x/cast?godoc=1)
- [exp](exp): contains experimental and/or unstable APIs. [docs](https://go.dw1.io/x/exp?godoc=1)
	- [exp/file](exp/file): an `os.File`-compatible API that prefers memory-mapped. [docs](https://go.dw1.io/x/exp/file?godoc=1)
	- [exp/gctuner](exp/gctuner): a lightweight GC tuning helper based on a heap. [docs](https://go.dw1.io/x/exp/gctuner?godoc=1)
	- [exp/sandboxec](exp/sandboxec): wraps os/exec with Landlock policy enforcement. [docs](https://go.dw1.io/x/exp/sandboxec?godoc=1)
- [hash/wyhash](hash/wyhash): a Go implementation of the wyhash non-cryptographic. [docs](https://go.dw1.io/x/hash/wyhash?godoc=1)
- [json](json): fast JSON encoding and decoding functionality. [docs](https://go.dw1.io/x/json?godoc=1)
- [regexp](regexp): selects the fastest regex engine available for a pattern. [docs](https://go.dw1.io/x/regexp?godoc=1)

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
