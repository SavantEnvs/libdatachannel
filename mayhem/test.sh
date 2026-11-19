#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own suite (test/*.cpp), driven by build/tests/mayhem-tests (mayhem/test_main.cpp, built
# by build.sh with normal flags). rlenv re-runs this air-gapped (only loopback, no other interface),
# where libjuice gathers no ICE host candidates, so the peer-to-peer connectivity tests (connectivity,
# negotiated, reliability, track, rtx/fir/rtcp-app integration, C API connectivity/track) cannot pass;
# they are not run. These upstream tests work offline and assert their results: SDP generation and
# parsing (simulcast, RTX, FIR), PEM certificates, video layers allocation, RTCP APP parsing/sending,
# and WebSocketServer (C++ and C API) over loopback TCP. One process per test.
runner="$SRC/build/tests/mayhem-tests"
[ -x "$runner" ] || { echo "missing $runner — mayhem/build.sh must build it" >&2; emit_ctrf "libdatachannel-tests" 0 1; exit 1; }
TESTS="pem simulcast_sdp_generation simulcast_sdp_parsing video_layers_allocation fir_sdp
  rtx_description_addrtx rtx_description_addrtx_no_audio rtcp_app_single_packet
  rtcp_app_compound_packet rtcp_app_empty_data rtcp_app_send rtcp_app_multiple_in_compound
  websocketserver capi_websocketserver"
passed=0; failed=0
log="$(mktemp)"
for t in $TESTS; do
  ( cd "$SRC/build/tests" && timeout 120 "$runner" "$t" ) >"$log" 2>&1
  rc=$?
  # A pass needs upstream's "*** Finished <name> test" line, the driver's clean summary and exit 0.
  if [ "$rc" -eq 0 ] && grep -qx "\*\*\* Finished $t test" "$log" \
     && grep -qx 'Succeeded: 1\. Failed: 0\.' "$log"; then
    passed=$((passed + 1)); echo "PASS $t"
  else
    failed=$((failed + 1)); echo "FAIL $t (rc=$rc)"; tail -20 "$log"
  fi
done
rm -f "$log"
emit_ctrf "libdatachannel-tests" "$passed" "$failed"
