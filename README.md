# copa-snyk

A [Copacetic](https://github.com/project-copacetic/copacetic) scanner plugin for Snyk Container.
It converts a `snyk container test --json` report into Copa's `v1alpha2` manifest, so
`copa patch --scanner snyk` can fix the OS packages Snyk reports. It only reads the report: no Snyk calls, no credentials.

## Install

```sh
go install github.com/amitramachandran/copa-snyk@latest   # or: make install
```

Copa finds plugins as `copa-<scanner>` on your `$PATH`.

## Usage

```sh
snyk container test $IMAGE --json > snyk.json
copa patch -i $IMAGE -r snyk.json --scanner snyk -t patched
```

> ⚠️ **Warning:** Large images can exceed Copa's default 5m timeout; add `--timeout 25m`.

Inspect the plugin output directly with `copa-snyk snyk.json | jq .`

## Support

| Area | Status |
|---|---|
| OS packages: Debian, Alpine, Rocky (deb / apk / rpm) | Tested end to end |
| Library packages (`--app-vulns`) | Parsed, but Node patching doesn't take effect: see [Known limitation](#known-limitation) |

Tested with Snyk CLI 1.1297.1, Copa 0.15.0 and Copa `main` (`9f75a57`):

| Image | Result |
|---|---|
| `debian:bookworm-20230612-slim` | 259 fixable findings -> 0 |
| `node:16.0-alpine3.13` | 72 fixable OS findings -> 0 |
| `rockylinux:9.0` | 700 findings -> 0 (80 packages) |
| `vulnerables/web-dvwa` (Debian 9) | Report parses; patching fails because Debian 9's apt repositories are gone |

### Yet to test

| Item | What's unverified |
|---|---|
| Ubuntu | Distro detection from `SNYK-UBUNTU*` IDs and `2004` -> `20.04` version conversion (unit-tested only) |
| RHEL, Amazon Linux, Oracle, Alma, CentOS, SUSE | Distro token mapping (unit-tested only); the rpm flow itself is verified on Rocky |
| `pip` -> `python-pkg` | Snyk found no pip project in my test image, so no real report exists |
| `gomodules` -> `gomod`, `golangbinary` -> `gobinary` | No real report |
| `nuget` -> `dotnet-core`, `yarn` -> `node-pkg` | No real report |
| `linux/arm64` images | Platform parsing is unit-tested; no real report |
| Library patching by Copa | Not confirmed for any ecosystem; Node is blocked (below) |

## Known limitation

Node.js library patching through a plugin has no effect. 
OS patching is unaffected. Library patching is also experimental in Copa (`COPA_EXPERIMENTAL=1`, `--pkg-types os,library`).

## How it maps

- **OS and version:** from the distro token in Snyk IDs (`SNYK-DEBIAN12-...`), else `docker.baseImage`.
  Alpine and Ubuntu versions become dotted (`318` -> `3.18`, `2004` -> `20.04`).
- **Arch and variant:** from `platform` (`linux/arm64/v8` -> `arm64`, `v8`).
- **Package name:** binary name from the last `from` entry (`source/binary@version`), since Copa installs by binary.
- **Rows:** one per fixable (package, CVE), with exact duplicates collapsed. Findings with no fix are skipped.
  rpm fixed versions keep Snyk's epoch (`2:4.9-15.el9`); Copa accepts it.
- **Skipped:** findings with `from: ["Upstream"]` / `SNYK-UPSTREAM-*` (software not installed by the package
  manager, e.g. a source-built Node.js). Copa can't upgrade them, and requesting them fails the whole patch.
- **Libraries** (nested `applications` array): `npm`/`yarn` -> `node-pkg`, `pip` -> `python-pkg`,
  `gomodules` -> `gomod`, `golangbinary` -> `gobinary`, `nuget` -> `dotnet-core`; others are skipped.
  All `fixedIn` versions are emitted comma-separated (`0.2.1,1.2.3`) for Copa to choose from.

## Development

```sh
make test    # fixtures in testdata/
make build   # ./dist/copa-snyk
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
