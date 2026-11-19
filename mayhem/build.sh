#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# libdatachannel needs its git submodules (deps/plog, usrsctp, libjuice, libsrtp); CI checks them
# out recursively and they are COPY'd into the image with the rest of the tree, so nothing is fetched.
for d in plog usrsctp libjuice libsrtp; do
  [ -f "deps/$d/CMakeLists.txt" ] || { echo "deps/$d is empty: check out submodules (git submodule update --init --recursive)" >&2; exit 1; }
done

# 1+2) Sanitized, SanCov-instrumented libdatachannel (+ bundled submodule deps) and every harness,
#      via mayhem/CMakeLists.txt, which add_subdirectory()s upstream's CMake project unchanged and
#      links each harness twice: with libFuzzer and with the standalone run-once driver.
#      Build dirs live under build/ (gitignored upstream), so `git clean -ffdX` removes them.
FUZZ_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S mayhem -B build/fuzz \
  -DCMAKE_BUILD_TYPE=None \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
  -DBUILD_SHARED_LIBS=OFF -DNO_EXAMPLES=ON -DNO_TESTS=ON \
  -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" -DSTANDALONE_FUZZ_MAIN="$STANDALONE_FUZZ_MAIN" \
  -DLSAN_OFF_SRC="$SRC/mayhem/lsan_off.cc"
FUZZERS="fuzz_description fuzz_candidate fuzz_rtcp_session fuzz_rtcp_handlers fuzz_h264_depacketizer
  fuzz_h265_depacketizer fuzz_av1_depacketizer fuzz_vp8_depacketizer fuzz_vp9_depacketizer
  fuzz_audio_depacketizer fuzz_peerconnection fuzz_websocketserver fuzz_websocket_client"
tgts=()
for f in $FUZZERS; do tgts+=(--target "$f" --target "$f-standalone"); done
cmake --build build/fuzz -j"$MAYHEM_JOBS" "${tgts[@]}"
for f in $FUZZERS; do
  install -m 0755 "build/fuzz/$f" "/mayhem/$f"
  install -m 0755 "build/fuzz/$f-standalone" "/mayhem/$f-standalone"
done

# 3) Upstream's own test suite (test/*.cpp -> `tests`), NORMAL flags, shared lib, separate tree.
cmake -S . -B build/tests -DCMAKE_BUILD_TYPE=RelWithDebInfo -DNO_EXAMPLES=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build/tests -j"$MAYHEM_JOBS" --target datachannel-tests
# mayhem/test_main.cpp: a driver over upstream's own test/*.cpp that runs named tests (test.sh
# runs the offline-capable subset, one per process). Linked against the normal-flags shared lib.
tsrc=""
for t in connectivity dtls negotiated reliability simulcast_sdp_generation simulcast_sdp_parsing \
         track video_layers_allocation capi_connectivity capi_track websocketserver \
         capi_websocketserver fir rtx rtcp_app; do
  tsrc="$tsrc test/$t.cpp"
done
$CXX -std=c++17 -O1 -g $COVERAGE_FLAGS -DRTC_ENABLE_MEDIA=1 -DRTC_ENABLE_WEBSOCKET=1 \
  -Iinclude -Iinclude/rtc -Isrc -Ideps/plog/include $tsrc mayhem/test_main.cpp \
  -Lbuild/tests -ldatachannel -Wl,-rpath,"$SRC/build/tests" -lpthread -o build/tests/mayhem-tests
