# Fuzz-harness build for libdatachannel (mayhem/build.sh drives it).
# Pulls in upstream's own CMake project unchanged and links every harness against the
# sanitized static library target `datachannel-static`, so CMake resolves the transitive
# dependencies (usrsctp, libjuice, libsrtp, plog submodules + OpenSSL) itself.
cmake_minimum_required(VERSION 3.13)
project(libdatachannel_fuzz C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIB_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE STRING "libFuzzer link flag")
set(STANDALONE_FUZZ_MAIN "" CACHE FILEPATH "LLVM run-once driver (C)")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/.. libdatachannel EXCLUDE_FROM_ALL)

# LSan off at build time (__lsan_is_turned_off), linked into every fuzz + standalone binary.
set(LSAN_OFF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/lsan_off.cc CACHE FILEPATH "lsan_off.cc")
add_library(lsan_off OBJECT ${LSAN_OFF_SRC})
add_library(standalone_main OBJECT ${STANDALONE_FUZZ_MAIN})
set_source_files_properties(${STANDALONE_FUZZ_MAIN} PROPERTIES LANGUAGE C)

set(FUZZERS
    fuzz_description fuzz_candidate fuzz_rtcp_session fuzz_rtcp_handlers
    fuzz_h264_depacketizer fuzz_h265_depacketizer fuzz_av1_depacketizer
    fuzz_vp8_depacketizer fuzz_vp9_depacketizer fuzz_audio_depacketizer
    fuzz_peerconnection fuzz_websocketserver fuzz_websocket_client)

foreach(f ${FUZZERS})
  add_executable(${f} ${CMAKE_CURRENT_SOURCE_DIR}/harnesses/${f}.cpp $<TARGET_OBJECTS:lsan_off>)
  target_link_libraries(${f} PRIVATE datachannel-static)
  target_link_options(${f} PRIVATE ${LIB_FUZZING_ENGINE})
  add_executable(${f}-standalone ${CMAKE_CURRENT_SOURCE_DIR}/harnesses/${f}.cpp
                 $<TARGET_OBJECTS:lsan_off> $<TARGET_OBJECTS:standalone_main>)
  target_link_libraries(${f}-standalone PRIVATE datachannel-static)
endforeach()

# fuzz_websocket_client computes the RFC 6455 Sec-WebSocket-Accept itself with OpenSSL's SHA-1
# (independently of the library's own implementation, which it checks against).
find_package(OpenSSL REQUIRED)
target_link_libraries(fuzz_websocket_client PRIVATE OpenSSL::Crypto)
target_link_libraries(fuzz_websocket_client-standalone PRIVATE OpenSSL::Crypto)

# The bundled third-party submodules (libjuice ICE, usrsctp SCTP, libsrtp) are dependencies, not the
# fuzz target: build them without sanitizers or SanCov (SPEC: dependencies stay uninstrumented).
# Instrumented, libjuice's picohash trips UBSan's -fsanitize=function on every PeerConnection.
foreach(dep juice-static usrsctp srtp2)
  if(TARGET ${dep})
    target_compile_options(${dep} PRIVATE -fno-sanitize=all)
  endif()
endforeach()
