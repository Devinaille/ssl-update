# Changelog

All notable changes to ssl-update will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
