# Changelog

All notable changes to ssl-update will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-09-02

### Fixed
- P1: `safeline.findByDomain` used exact-string match, missing the
  case where the WAF stored the cert as the bare apex (`a.com`)
  while we queried with the wildcard (`*.a.com`). That created
  duplicate cert entries instead of upserting. The new
  `domainVariants()` helper tries both forms. Regression test
  added. (`internal/destination/safeline/safeline.go`)
- P1: `show-state` now displays timestamps with explicit `UTC`
  suffix so users in non-UTC time zones don't mistake local-time
  output for the actual timestamp. State is always stored in UTC.
  (`internal/cli/show_state.go`)
- `cli/root.go` PersistentPreRunE returned raw errors from
  `config.LoadFile` and `setupLogger`, so the main entry point's
  `errors.As(*StartupErr)` check failed and config / logger errors
  exited with code 1 instead of 2. Now wrapped with `StartupError`
  so all startup failures map consistently to exit 2 (matching
  README's documented exit-code contract).

### Changed
- P1: `dry-run` now prints each destination's effective `cert_name`
  (via `Destination.CertName()`) so users with config overrides
  see what would actually be pushed, not the raw sanitized domain.
- P2: `cert.ReadBundle` no longer takes a `domains []string`
  parameter. The bundle's `Domains` field is now always populated
  from the leaf certificate's `DNSNames` SAN list, which is the
  only correct source. Previously the runner passed `nil` for that
  parameter, leaving the field unused in production.
- P2: runner's semaphore acquisition moved from the main loop into
  the goroutine itself with a `select` that also watches
  `ctx.Done()`. Previously the main loop blocked on
  `sem <- struct{}{}`, which (a) prevented the `ctx.Err()` check
  at the top of the next iteration from running while a slow
  destination held the slot, and (b) made concurrency effectively
  sequential at startup. The top-of-loop `ctx.Err()` check is kept
  because Go's `select` is non-deterministic when both cases are
  ready, so a pre-cancelled context needs a deterministic bail
  path. (`internal/runner/runner.go`)
- P2: `isRequired` (O(n²) linear scan per result) replaced with
  `requiredMap` (O(1) lookup precomputed once before the result
  loop). Trivial gain at current destination counts but cleaner
  and O(n) overall.
- Build pipeline ships **linux-amd64 only**. arm64 was removed
  because the maintainer doesn't deploy to ARM and can't verify it.
  The local `make` target still supports `make build-linux-arm64`
  for ad-hoc local builds.

### Added
- CI: `test` → `build` → `smoke-test` → `release` pipeline under
  `.gitea/workflows/build.yml`. The smoke-test job downloads the
  freshly-built binary and exercises it against dummy
  configurations (no network services required), covering 30
  assertions across:
  - Tier 1: binary structural (file/ldd/version output)
  - Tier 2: 10 config-validation failure modes (missing file, bad
    YAML, missing/duplicate destination names, invalid log
    level/format, missing cert paths, bad PEM, missing/unknown
    destination type)
  - Tier 3: error strategies (--dry-run, --only, --timeout,
    --skip-state, show-state table/json, list-sites on wrong type,
    log file actually written, log.format=json produces valid JSON)
- CI: release job uses Gitea's native REST API (no
  `softprops/action-gh-release`, which calls GitHub-only endpoints
  and 405s on Gitea). Pre-release flag auto-detected from tag name
  per semver: `vX.Y.Z` = stable, `vX.Y.Z-<suffix>` = pre-release.
- CI: release assets are uploaded with names like
  `ssl-update-v0.1.4-linux-amd64` (binary) and
  `ssl-update-v0.1.4-linux-amd64.sha256sum` (checksum file).
  Checksum entries are rewritten in place so `sha256sum -c` works
  after download.
- `scripts/smoke-test.sh`: the battery of checks invoked by CI,
  also runnable locally as `BIN=/path/to/ssl-update
  scripts/smoke-test.sh`. Color-coded PASS/FAIL output suitable
  for CI log scraping.

## [0.1.3] - 2026-09-02

### Fixed
- `safeline` `postJSON` no longer ignores the error from
  `http.NewRequestWithContext`. With a nil context (which happened when
  `log.file` was empty), this caused a nil-pointer panic in `setAuth`.
  (`internal/destination/safeline/safeline.go`)
- `run` `--timeout` flag is now actually applied to the request context.
  Previously the value was captured into `runOpts` but never wired into
  `context.WithTimeout`, so a hung destination could outlast the
  declared overall timeout. The runner also now checks `ctx.Err()` at
  the top of each iteration so a cancelled context stops spawning new
  destination goroutines. (`internal/cli/run.go`, `internal/runner/runner.go`)
- `--skip-state` no longer leaks `state-*.json.tmp` files into the
  current working directory. Two layers of defence: `cli/run.go` skips
  `state.Save()` when `--skip-state` is set, and `state.Save()` itself
  is a no-op when the backing path is empty. (`internal/cli/run.go`,
  `internal/state/state.go`)
- `cli/root.go` always injects a context (was conditional on `closer != nil`).
  When `log.file` was empty, downstream destinations received a nil
  context, causing every API call to fail. (`internal/cli/root.go`)

### Changed
- Logger output routed through `log/slog` instead of raw `fmt.Printf`
  / `fmt.Fprintf`. The `log.level`, `log.format`, and `log.file` config
  fields (which were previously dead code) now actually take effect.
  CLI surface is unchanged: messages still carry `[INFO]` / `[WARN]` /
  `[ERROR]` prefixes for grep compatibility, plus structured key-value
  pairs (`dest=`, `err=`, `duration=`). (`internal/cli/run.go`,
  `internal/cli/validate.go`, `internal/runner/runner.go`,
  `internal/destination/safeline/safeline.go`,
  `internal/destination/aliyun_esa/aliyun_esa.go`)
- `dry-run` now prints the destination's effective `cert_name` (via
  `Destination.CertName()`) rather than the raw sanitized domain, so
  config overrides are visible in the output.

### Added
- Debug-level structured log line emitted by each destination at the
  start of `Deploy`, including fingerprint, cert PEM size, and hint id.
  Cert body and private key are **never** logged regardless of level.
- Three regression tests covering the fixes above:
  `TestDeploy_NilContext_ReturnsError`,
  `TestSave_EmptyPathIsNoop`,
  `TestRun_HonorsContextCancellation`.

## [0.1.2] - 2026-09-01

### Added
- Aliyun Edge Security Acceleration (ESA) destination plugin. Hand-written
  Aliyun v3 RPC signing (`internal/destination/aliyun_esa/sign.go`) — no
  official SDK dependency. Includes `ListSites` support for site_id
  discovery via the `list-sites` subcommand. (`internal/destination/aliyun_esa/`)
- `list-sites` subcommand to discover ESA site_id values that the
  console does not display. (`internal/cli/list_sites.go`)

## [0.1.1] - 2026-08-31

### Fixed
- `safeline` was sending the wrong authentication header. The WAF
  middleware requires the literal header `X-SLCE-API-TOKEN`; earlier
  code (and the WAF's own swagger) used the placeholder name
  `API-TOKEN`, which the middleware silently rejected with HTTP 401.
- `safeline` cert upload used `type=1` per the swagger, but recent WAF
  versions reject this with HTTP 500 "Error occurred when extracting
  params". Verified working value across community integrations is
  `type=2`. (`internal/destination/safeline/safeline.go`)
- `safeline` `api_url` / `api_token` empty values now produce a clear
  startup error instead of a confusing HTTP failure later.

## [0.1.0] - 2026-08-31

### Added
- Initial release. Plugin-style cert-push tool designed to be triggered
  from acme.sh's `--reloadcmd`.
- Two built-in destination plugins: `safeline` (长亭雷池 WAF Community
  Edition) and `aliyun_esa` (added in 0.1.2).
- Subcommands: `run`, `validate`, `show-state`, `list-sites`, `version`.
- YAML configuration with environment-variable fallback for acme.sh
  integration (`$LE_CERT_PATH`, `$LE_KEY_PATH`, `$Le_DomainMain`).
- State persistence (`state.json`) with atomic writes; records
  per-`(destination, cert_name)` cert_id so renewals update in place
  rather than accumulate duplicate cert entries in the service.
- Per-destination failure policy: `required: true` failures exit 1,
  `required: false` failures only emit a warning.
- Exit codes: 0 = success, 1 = required destination failed, 2 = startup
  error (config / cert / unknown destination type).
- English and Chinese README; `config.example.yaml`; logrotate config.
- Linux amd64 and arm64 static binaries produced via Makefile.
