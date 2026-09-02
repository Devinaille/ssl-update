#!/usr/bin/env bash
# scripts/smoke-test.sh — Tier 1/2/3 + 7 smoke tests for ssl-update.
#
# Runs a battery of checks against a built binary: structural (file/ldd),
# config validation, error strategies, and CLI flag wiring.
# No external services required — all tests use unreachable destinations.
#
# Usage:
#   BIN=/path/to/ssl-update scripts/smoke-test.sh
#
# Exits 0 if every check passes, 1 if any fails. Output is a flat
# PASS/FAIL table suitable for CI log scraping.

set -uo pipefail

BIN="${BIN:-./ssl-update}"
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT

PASS=0
FAIL=0
FAILED=()

pass() { printf "  \033[32mPASS\033[0m  %s\n" "$1"; PASS=$((PASS+1)); }
fail() { printf "  \033[31mFAIL\033[0m  %s\n      %s\n" "$1" "$2"; FAIL=$((FAIL+1)); FAILED+=("$1"); }

# expect_exit NAME WANT_EXIT CMD...
expect_exit() {
    local name="$1" want="$2"; shift 2
    "$@" >/dev/null 2>"$TESTDIR/err"
    local got=$?
    if [ "$got" = "$want" ]; then
        pass "$name"
    else
        local hint
        hint=$(head -c 200 "$TESTDIR/err" | tr '\n' ' ')
        fail "$name" "expected exit $want, got $got: $hint"
    fi
}

expect_stdout_contains() {
    local name="$1" want="$2"; shift 2
    local out
    out=$("$@" 2>/dev/null)
    # Use grep -F (fixed string) to avoid glob interpretation of [ ] etc.
    if printf '%s\n' "$out" | grep -qF -- "$want"; then
        pass "$name"
    else
        fail "$name" "stdout missing '$want'; got: ${out:0:200}"
    fi
}

# === Prereqs ===
if ! command -v openssl >/dev/null; then
    echo "FATAL: openssl not on PATH"; exit 2
fi
if ! command -v python3 >/dev/null; then
    echo "FATAL: python3 not on PATH (needed for JSON validation)"; exit 2
fi

if [ ! -x "$BIN" ]; then
    echo "FATAL: BIN=$BIN is not executable"; exit 2
fi

# === Setup: dummy cert ===
mkdir -p "$TESTDIR/cert"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$TESTDIR/cert/key.pem" \
    -out    "$TESTDIR/cert/cert.pem" \
    -subj "/CN=example.com" \
    -addext "subjectAltName=DNS:example.com,DNS:www.example.com" \
    2>/dev/null
[ -s "$TESTDIR/cert/cert.pem" ] || { echo "FATAL: openssl cert gen failed"; exit 2; }

echo "== Tier 1: binary smoke =="

expect_exit          "version exits 0"                0 "$BIN" version
expect_stdout_contains "version output has types"     "destination types: [aliyun_esa safeline]" "$BIN" version
expect_exit          "--help exits 0"                 0 "$BIN" --help

if file "$BIN" | grep -qE "ELF.*executable.*statically linked"; then
    pass "file: ELF executable, statically linked"
else
    fail "file: ELF executable, statically linked" "$(file "$BIN")"
fi

# ldd check dropped: the 'file' check above already confirms static
# linkage. ldd's exact output string ("not a dynamic executable" vs
# "statically linked") varies across glibc versions and isn't worth
# a flaky test.

echo
echo "== Tier 2: config validation =="

expect_exit "missing config file → exit 2" 2 \
    "$BIN" --config /no/such/file.yaml run

cat > "$TESTDIR/bad-yaml.conf" <<'EOF'
destinations: [
EOF
expect_exit "bad YAML → exit 2" 2 \
    "$BIN" --config "$TESTDIR/bad-yaml.conf" run

cat > "$TESTDIR/no-name.conf" <<'EOF'
log: {level: info, format: text}
destinations:
  - {type: safeline, config: {api_url: x, api_token: y}}
EOF
expect_exit "destination missing name → exit 2" 2 \
    "$BIN" --config "$TESTDIR/no-name.conf" run

cat > "$TESTDIR/duplicate.conf" <<'EOF'
log: {level: info, format: text}
destinations:
  - {name: dup, type: safeline, config: {api_url: x, api_token: y}}
  - {name: dup, type: safeline, config: {api_url: x, api_token: y}}
EOF
expect_exit "duplicate destination name → exit 2" 2 \
    "$BIN" --config "$TESTDIR/duplicate.conf" run

cat > "$TESTDIR/bad-level.conf" <<'EOF'
log: {level: verbose}
destinations: []
EOF
expect_exit "invalid log level → exit 2" 2 \
    "$BIN" --config "$TESTDIR/bad-level.conf" run

cat > "$TESTDIR/bad-format.conf" <<'EOF'
log: {format: yaml}
destinations: []
EOF
expect_exit "invalid log format → exit 2" 2 \
    "$BIN" --config "$TESTDIR/bad-format.conf" run

cat > "$TESTDIR/no-cert.conf" <<'EOF'
log: {level: info, format: text}
cert: {cert_path: "", key_path: "", domain: ""}
destinations: []
EOF
expect_exit "empty cert paths → exit 2" 2 \
    "$BIN" --config "$TESTDIR/no-cert.conf" run

echo "not pem" > "$TESTDIR/bad.pem"
cat > "$TESTDIR/bad-pem.conf" <<EOF
log: {level: info, format: text}
cert: {cert_path: "$TESTDIR/bad.pem", key_path: "$TESTDIR/bad.pem", domain: x}
destinations: []
EOF
expect_exit "bad PEM → exit 2" 2 \
    "$BIN" --config "$TESTDIR/bad-pem.conf" run

cat > "$TESTDIR/no-type.conf" <<'EOF'
log: {level: info, format: text}
destinations:
  - {name: x, config: {}}
EOF
expect_exit "destination missing type → exit 2" 2 \
    "$BIN" --config "$TESTDIR/no-type.conf" run

cat > "$TESTDIR/unknown-type.conf" <<'EOF'
log: {level: info, format: text}
destinations:
  - {name: x, type: not_a_real_type, config: {}}
EOF
expect_exit "unknown destination type → exit 2" 2 \
    "$BIN" --config "$TESTDIR/unknown-type.conf" run

echo
echo "== Tier 3: error strategies & flag wiring =="

cat > "$TESTDIR/dummy.conf" <<EOF
cert:
  cert_path: "$TESTDIR/cert/cert.pem"
  key_path:  "$TESTDIR/cert/key.pem"
  domain: example.com
state: {path: "$TESTDIR/state.json"}
log: {level: info, format: text, file: "$TESTDIR/run.log"}
concurrency: 2
destinations:
  - {name: unreachable-opt, type: safeline, required: false,
     config: {api_url: https://127.0.0.1:1, api_token: x, verify_tls: false}}
  - {name: unreachable-req, type: aliyun_esa, required: true,
     config: {access_key_id: AKIAx, access_key_secret: y, site_id: 1}}
EOF

# dry-run: doesn't actually deploy
expect_exit "run --dry-run → exit 0" 0 \
    "$BIN" --config "$TESTDIR/dummy.conf" run --dry-run

dry_out=$("$BIN" --config "$TESTDIR/dummy.conf" run --dry-run 2>&1)
if printf '%s\n' "$dry_out" | grep -qF "unreachable-opt" && \
   printf '%s\n' "$dry_out" | grep -qF "unreachable-req" && \
   printf '%s\n' "$dry_out" | grep -qF "[DRY-RUN]"; then
    pass "dry-run lists all destinations"
else
    fail "dry-run lists all destinations" "${dry_out:0:200}"
fi

# dry-run should NOT touch state.json
if [ ! -f "$TESTDIR/state.json" ]; then
    pass "dry-run does not create state.json"
else
    fail "dry-run does not create state.json" "state.json was created"
fi

# Real run with required failure: exit 1
expect_exit "run with required failure → exit 1" 1 \
    "$BIN" --config "$TESTDIR/dummy.conf" run

# Required fail should be in log + WARN for optional
log_content=$(cat "$TESTDIR/run.log" 2>/dev/null || echo "")
if printf '%s\n' "$log_content" | grep -qF "deploy failed" && \
   printf '%s\n' "$log_content" | grep -qF "unreachable-req" && \
   printf '%s\n' "$log_content" | grep -qF "unreachable-opt"; then
    pass "log records both required and optional failures"
else
    fail "log records both required and optional failures" "log: ${log_content:0:300}"
fi

# --only filter: only the opt destination runs. It's required:false
# and unreachable, so the overall exit is 0 (failure tolerated).
expect_exit "run --only unreachable-opt → exit 0" 0 \
    "$BIN" --config "$TESTDIR/dummy.conf" run --only unreachable-opt

# --only no match → exit 2
expect_exit "run --only nonexistent → exit 2" 2 \
    "$BIN" --config "$TESTDIR/dummy.conf" run --only nonexistent

# --timeout: should exit in < 5s (we set 1s, http.Client.Timeout is 30s)
start=$(date +%s)
"$BIN" --config "$TESTDIR/dummy.conf" run --only unreachable-opt --timeout 1s >/dev/null 2>&1 || true
elapsed=$(( $(date +%s) - start ))
if [ "$elapsed" -lt 5 ]; then
    pass "--timeout 1s honored (elapsed ${elapsed}s)"
else
    fail "--timeout 1s honored" "elapsed ${elapsed}s (>5s suggests --timeout is a no-op)"
fi

# --skip-state: should not leave tmp files in CWD
SKIPDIR=$(mktemp -d)
( cd "$SKIPDIR" && "$BIN" --config "$TESTDIR/dummy.conf" run --skip-state >/dev/null 2>&1 || true )
tmp_count=$(find "$SKIPDIR" -maxdepth 1 -name 'state-*.json.tmp' | wc -l)
rm -rf "$SKIPDIR"
if [ "$tmp_count" -eq 0 ]; then
    pass "--skip-state leaves no tmp files in CWD"
else
    fail "--skip-state leaves no tmp files in CWD" "found $tmp_count"
fi

# show-state (no deploys ever succeeded → empty)
expect_exit "show-state → exit 0" 0 \
    "$BIN" --config "$TESTDIR/dummy.conf" show-state

show_out=$("$BIN" --config "$TESTDIR/dummy.conf" show-state 2>&1)
if [[ "$show_out" == *"no deployments recorded"* ]]; then
    pass "show-state shows empty placeholder"
else
    fail "show-state shows empty placeholder" "${show_out:0:200}"
fi

# show-state --json
expect_exit "show-state --json → exit 0" 0 \
    "$BIN" --config "$TESTDIR/dummy.conf" show-state --json

json_out=$("$BIN" --config "$TESTDIR/dummy.conf" show-state --json 2>&1)
if echo "$json_out" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "show-state --json is valid JSON"
else
    fail "show-state --json is valid JSON" "${json_out:0:200}"
fi

# list-sites on non-aliyun_esa type → non-zero exit
expect_exit "list-sites on safeline → exit non-zero" 1 \
    "$BIN" --config "$TESTDIR/dummy.conf" list-sites --name unreachable-opt

# log.file is actually written (we already ran run above; check non-empty)
if [ -s "$TESTDIR/run.log" ]; then
    pass "log.file is written"
else
    fail "log.file is written" "log file empty or missing"
fi

# log.format=json produces parseable JSON
cat > "$TESTDIR/dummy-json.conf" <<EOF
cert:
  cert_path: "$TESTDIR/cert/cert.pem"
  key_path:  "$TESTDIR/cert/key.pem"
  domain: example.com
state: {path: "$TESTDIR/state2.json"}
log: {level: info, format: json, file: "$TESTDIR/run-json.log"}
concurrency: 2
destinations:
  - {name: unreachable-opt, type: safeline, required: false,
     config: {api_url: https://127.0.0.1:1, api_token: x, verify_tls: false}}
EOF

"$BIN" --config "$TESTDIR/dummy-json.conf" run >/dev/null 2>&1 || true
if [ -s "$TESTDIR/run-json.log" ] && \
   head -1 "$TESTDIR/run-json.log" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "log.format=json produces valid JSON"
else
    first_line=$(head -1 "$TESTDIR/run-json.log" 2>/dev/null || echo "(empty)")
    fail "log.format=json produces valid JSON" "first line: $first_line"
fi

echo
echo "== Summary =="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "  Failed tests:"
    for t in "${FAILED[@]}"; do
        echo "    - $t"
    done
    exit 1
fi
echo "  All $(printf '%d' "$PASS") checks passed."
exit 0
