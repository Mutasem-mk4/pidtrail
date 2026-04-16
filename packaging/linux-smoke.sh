#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "linux-smoke requires Linux" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "linux-smoke requires root so pidtrail can attach Linux tracepoints" >&2
  exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
tmpdir="$(mktemp -d)"
bindir="$tmpdir/bin"
mkdir -p "$bindir"

server_pid=""
process_trace_pid=""

cleanup() {
  if [ -n "$process_trace_pid" ]; then
    wait "$process_trace_pid" 2>/dev/null || true
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

fail() {
  echo "linux smoke failed: $*" >&2
  exit 1
}

assert_file() {
  [ -s "$1" ] || fail "expected non-empty file: $1"
}

assert_grep() {
  pattern="$1"
  file="$2"
  grep -q "$pattern" "$file" || fail "missing pattern $pattern in $file"
}

build_fixture() {
  out="$1"
  pkg="$2"
  (
    cd "$repo_root"
    go build -mod=vendor -trimpath -buildvcs=false -o "$out" "$pkg"
  )
}

assert_report_bundle() {
  report_dir="$1"
  events="$report_dir/events.jsonl"
  summary="$report_dir/summary.json"
  assert_file "$events"
  assert_file "$summary"
  assert_grep '"kind":"process"' "$events"
  assert_grep '"kind":"file"' "$events"
  assert_grep '"kind":"network"' "$events"
  assert_grep '"operation":"connect"' "$events"
  assert_grep '"total_events":' "$summary"
}

build_fixture "$bindir/pidtrail" ./cmd/pidtrail
build_fixture "$bindir/fixturesrv" ./examples/http-fixture-server
build_fixture "$bindir/fixturework" ./examples/http-smoke-workload

"$bindir/pidtrail" --pid $$ --quiet --diagnose --report-dir "$tmpdir/diagnose" >"$tmpdir/diagnose.log" 2>&1
assert_file "$tmpdir/diagnose/events.jsonl"
assert_file "$tmpdir/diagnose/summary.json"
assert_grep '"kind":"diagnostic"' "$tmpdir/diagnose/events.jsonl"
assert_grep 'platform: linux' "$tmpdir/diagnose/events.jsonl"

"$bindir/fixturesrv" >"$tmpdir/server.log" 2>&1 &
server_pid=$!
sleep 1

"$bindir/pidtrail" --quiet --report-dir "$tmpdir/command-report" --duration 8s -- "$bindir/fixturework" >"$tmpdir/command.log" 2>&1
assert_report_bundle "$tmpdir/command-report"
assert_grep '/etc/hosts' "$tmpdir/command-report/events.jsonl"
assert_grep '127.0.0.1:18080' "$tmpdir/command-report/events.jsonl"

"$bindir/fixturework" >"$tmpdir/pid-workload.log" 2>&1 &
workload_pid=$!
"$bindir/pidtrail" --quiet --report-dir "$tmpdir/pid-report" --pid "$workload_pid" --duration 8s >"$tmpdir/pid.log" 2>&1
wait "$workload_pid"
assert_report_bundle "$tmpdir/pid-report"

"$bindir/pidtrail" --quiet --report-dir "$tmpdir/process-report" --process fixturework --duration 8s >"$tmpdir/process.log" 2>&1 &
process_trace_pid=$!
sleep 2
"$bindir/fixturework" >"$tmpdir/process-workload.log" 2>&1
wait "$process_trace_pid"
process_trace_pid=""
assert_report_bundle "$tmpdir/process-report"

printf 'linux smoke passed\n'
