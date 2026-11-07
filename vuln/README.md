# go.dw1.io/x/vuln

`govulnbump` upgrades Go dependencies that have known vulnerabilities to
versions that fix them. It runs the same scan as
[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), which
only reports, and then makes the upgrades with `go get`.

## Install

```sh
go install go.dw1.io/x/vuln/cmd/govulnbump@latest
```

## Use

Run it in the module to fix:

```sh
govulnbump -n ./...   # print the upgrades
govulnbump ./...      # make them
```

By default, `govulnbump` upgrades only modules whose vulnerable functions
your code calls, as govulncheck reports them. Run `govulnbump -h` for the
flags. The [package documentation](https://pkg.go.dev/go.dw1.io/x/vuln/cmd/govulnbump)
also covers how versions are chosen, exit codes, and limitations.

## Code from golang.org/x/vuln

The scanner is [golang.org/x/vuln/scan](https://pkg.go.dev/golang.org/x/vuln/scan),
a regular dependency. golang.org/x/vuln keeps its JSON message types and
version helpers internal, so these files are copied from golang.org/x/vuln
v1.9.0 (commit e672cbe), with only their import paths changed:

- `internal/govulncheck/govulncheck.go`
- `internal/osv/osv.go`, `internal/osv/review_status.go`
- `internal/semver/semver.go`, `internal/semver/affects.go`, and their tests

When you upgrade golang.org/x/vuln, copy these files, and the `LICENSE` file
in each of their directories, from the same version. govulnbump checks the
protocol version of the scanner's output, and fails if its major version
differs from the copied types'.

## License

govulnbump is released under the Apache-2.0 license, in [LICENSE](LICENSE).
The files copied from golang.org/x/vuln keep their BSD 3-Clause license, in
the `LICENSE` file of each directory that holds them. [NOTICE](NOTICE)
lists them.
