# AGENTS.md

ssl-update: a single Go binary that pushes acme.sh-renewed certificates to
multiple destinations (Safeline WAF CE, Aliyun ESA, Next Terminal) from one YAML
config file. It uses a plug-in architecture: each destination is a Go package
implementing the `destination.Destination` interface and self-registering via
`init()`. User-facing docs are in Chinese (`README.zh-CN.md`).

## Commands

The Go module lives at the repo root (`module ssl-update`). The entry point is
`cmd/ssl-update/main.go` (wiring only); all logic is under `internal/`.

```bash
gofmt -l .                       # must print nothing
go vet ./...
go test -race -count=1 ./...     # CI order is gofmt -> vet -> test -> build
go test -race ./internal/destination/next_terminal/...   # one package
go build -o ssl-update ./cmd/ssl-update
```

- Makefile: `make build` (current platform), `make build-linux-amd64`,
  `make build-linux-arm64`, `make build-all`, `make test`, `make vet`,
  `make fmt`, `make clean`, `make version`. `VERSION` is defined in the
  Makefile and is exported into the binary via
  `-X ssl-update/internal/cli.Version`. Override with `make VERSION=dev-x ...`.
- Smoke tests (needs `openssl`, `python3`; no external services — every
  destination points at `127.0.0.1:1`):
  `BIN=/path/to/ssl-update bash scripts/smoke-test.sh`.
- Running the binary needs a config: `ssl-update --config <file> <cmd>`; the
  default is `/etc/ssl-update/config.yaml`. cert/key/domain fall back to
  acme.sh's `LE_CERT_PATH` / `LE_KEY_PATH` / `Le_DomainMain` env vars.
- Exit codes: `0` success (or only `required: false` failures), `1` a required
  destination failed, `2` startup failure (bad config / unreadable cert /
  unknown type).

## Layout

- `cmd/ssl-update/main.go` — wiring only; blank-imports each destination
  package so its `init()` runs. Add new types here.
- `internal/destination` — the `Destination` interface, `DeployResult`, the
  sentinel errors (`ErrInvalidConfig`, `ErrAuth`, `ErrNetwork`,
  `ErrCertNotFound`, `ErrCertRejected`, `ErrQuota`), and the type registry.
- `internal/destination/<type>/` — one package per push target (`safeline`,
  `aliyun_esa`, `next_terminal`). Each has `const TypeName`, an `init()` that
  calls `destination.Register`, and `New/Name/CertName/Deploy/Validate`.
- `internal/cert` — `ReadBundle` (PEM cert+key, SANs, NotAfter) and
  `SanitizeName` (`*.a.com` → `wildcard-a-com`).
- `internal/config` — YAML load/validate (`cert`, `state`, `log`,
  `concurrency`, `destinations`).
- `internal/runner` — parallel dispatch, per-destination `required` failure
  policy, state persistence.
- `internal/state` — `state.json`, keyed `<dest_name>:<cert_name>`, stores the
  service-side cert id + fingerprint so renewals update in place.
- `internal/cli` — cobra commands: `run`, `validate`, `show-state`,
  `list-sites`, `version`.

## Adding a destination

1. Create `internal/destination/<type>/<type>.go`. Implement the four methods.
   Wrap config problems with `destination.ErrInvalidConfig`; map HTTP failures
   onto the sentinel errors so the runner/exit codes stay meaningful.
2. `init()` → `destination.Register(TypeName, New)`; add a blank import in
   `cmd/ssl-update/main.go`.
3. `CertName(b)` MUST be deterministic for the same bundle — it is the state
   key. `Deploy` must return `DeployResult.CertName == CertName(b)` and should
   use `certIDHint` to update the existing record rather than create a
   duplicate. Prefer an idempotent "update or create" call.
4. Add `httptest` unit tests. `verify_tls` defaults to **true**; tests that use
   a self-signed test server must either set `verify_tls: false` or inject
   `ts.Client()` into the destination's `hc`.
5. Document the fields in `config.example.yaml`, both READMEs, and add a
   `CHANGELOG.md` entry.

`ssl-update run --dry-run` prints each destination's `CertName()` without
calling `Deploy`; `--log-level debug` will print certificate bytes, so never use
debug in production.

## Branch & release flow

The model follows `Devinaille/cloud-sync`.

- **All development happens on `dev`.** Push to `dev` → `.github/workflows/dev.yml`
  runs gofmt/vet/test, builds a static linux/amd64 binary stamped
  `dev-<UTC timestamp>-<short sha>`, uploads it as an artifact, and runs smoke
  tests against it. **No GitHub Release is created on `dev`.**
- `.github/workflows/ci.yml` runs on push to `main` and on PRs to `main`/`dev`:
  gofmt → vet → test (race) → build → smoke. This is the merge gate.
- `.github/workflows/release.yml` is tag-triggered (`v*`) and **fails unless the
  tag commit is an ancestor of `main`**. To cut one:
  ```bash
  git checkout main && git merge --no-ff dev && git push origin main
  git tag vX.Y.Z-rc1 && git push origin vX.Y.Z-rc1   # pre-release (RC)
  git tag vX.Y.Z     && git push origin vX.Y.Z       # full release
  ```
  Tags containing `-` are published as pre-releases (`prerelease: true`).
- Never tag on `dev`; never release from a non-`main` commit. Bump `VERSION` in
  the Makefile and add a `CHANGELOG.md` entry as part of the release prep.

## References

- `config.example.yaml` — full config surface.
- `docs/superpowers/specs/` — design intent.
- Commit messages use Conventional Commits (see `git log --oneline`).
