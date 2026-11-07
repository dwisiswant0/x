/*
Govulnbump upgrades dependencies that have known vulnerabilities to versions
that fix them.

It runs the same scan as govulncheck (golang.org/x/vuln/cmd/govulncheck) and
upgrades each module that the scan reports to the lowest version that fixes
the reported vulnerabilities. Then it scans again, and repeats until a scan
finds nothing it can upgrade.

# Usage

	govulnbump [flags] [patterns]

Run govulnbump in the module to fix. Patterns must be directory patterns, such
as ./cmd/app, because govulnbump passes them to go get. At levels symbol and
package, they default to ./...:

	$ govulnbump ./...

To print the upgrades without making them, use -n:

	$ govulnbump -n ./...

Each round of upgrades is a single go get command, so the go command keeps
go.mod and go.sum consistent. After a round that changes go.mod, govulnbump
runs go mod vendor if vendor/modules.txt exists. Progress and the go command's
output go to standard error.

When it finishes, govulnbump reports on standard output:

  - each module that was vulnerable at the start, from its version then to
    its version now, with the advisories that the upgrade fixed
  - other version changes in go.mod, such as requirements that the upgrades
    raised and a raised go line, which also raises the minimum Go version of
    modules that depend on yours. These include modules that a later round
    upgraded for advisories that an earlier upgrade introduced.
  - the vulnerabilities it could not fix, and why
  - at the default level, the vulnerabilities in packages your code imports
    but doesn't call, which -scan=package would also fix

If govulnbump fails after it has changed go.mod, it reports those changes
before the error.

The flags are:

	-C dir
		Change to dir before running.
	-db url
		Use the vulnerability database at url. The default is
		https://vuln.go.dev.
	-n
		Report the upgrades and the go get command that makes them,
		without running it.
	-scan level
		Scan at level symbol, package, or module, as govulncheck does.
		The default, symbol, upgrades only modules whose vulnerable
		functions your code calls. Level package also upgrades modules
		whose vulnerable packages your code imports, and level module
		upgrades every vulnerable module that the build needs. Level
		module accepts no patterns.
	-tags list
		Use the comma-separated build tags in list.
	-test
		Also scan test files, and pass -t to go get.
	-toolchain
		Fix standard library vulnerabilities by raising the go.mod
		toolchain line with go get toolchain@goX.Y.Z. This changes the
		toolchain that builds this module, not the go line that
		dependents inherit. GOTOOLCHAIN must allow switching
		toolchains: auto, path, or a value ending in +auto or +path.

Without -toolchain, govulnbump reports standard library vulnerabilities and
the Go release that fixes them.

# Choosing versions

For each vulnerable module, govulnbump picks the lowest version that its
advisories list as fixed and that none of them affects. Only advisories that
the scan reports at the selected level count. If the new version has a
different vulnerability, the next scan finds it.

govulnbump never lowers a version. It reports, without upgrading:

  - modules with no fixed version, or whose fixed versions go.mod excludes
  - modules that a replace directive names, because go get can't change them
  - vulnerabilities in the main module

# Exit codes

	0  No vulnerabilities remain at the selected level.
	1  An error occurred.
	2  The command line is invalid.
	3  Vulnerabilities remain at the selected level. With -n, this
	   includes vulnerabilities that the upgrades would fix.

# Limitations

  - Workspaces (go.work) are not supported. Run govulnbump with GOWORK=off
    in each module.
  - With -n, govulnbump shows only the first round of upgrades, because later
    rounds depend on the versions that go get selects.
  - At level module, govulnbump checks the same modules as
    govulncheck -scan=module: those that the package in the current
    directory needs.
*/
package main
