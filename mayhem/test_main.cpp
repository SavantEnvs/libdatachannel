// Driver for upstream's own test suite (test/*.cpp) used by mayhem/test.sh.
// Upstream's test/main.cpp runs every test in one process, including tests that need a
// non-loopback network interface (ICE host candidates) or an external service. This driver
// registers the same upstream test functions and runs only the ones named on the command
// line, each wrapped like upstream's Test::run(), so test.sh can run the suite offline
// (rlenv re-runs it air-gapped) one test per process.
#include "../test/test.hpp"
#include <rtc/rtc.hpp>

#include <chrono>
#include <cstring>
#include <future>
#include <map>
#include <string>

using namespace std::chrono_literals;

TestResult test_connectivity();
TestResult test_connectivity_fail_on_wrong_fingerprint();
TestResult test_dtls_startup_after_remote_description();
TestResult test_pem();
TestResult test_negotiated();
TestResult test_reliability();
TestResult test_simulcast_sdp_generation();
TestResult test_simulcast_sdp_parsing();
TestResult test_track();
TestResult test_video_layers_allocation();
TestResult test_fir_sdp();
TestResult test_fir_offer_yes_answer_yes();
TestResult test_rtx_attribute();
TestResult test_rtx_description_addrtx();
TestResult test_rtx_description_addrtx_no_audio();
TestResult test_rtx_dropped_packet();
TestResult test_rtx_multi_codec();
TestResult test_rtcp_app_single_packet();
TestResult test_rtcp_app_compound_packet();
TestResult test_rtcp_app_empty_data();
TestResult test_rtcp_app_send();
TestResult test_rtcp_app_multiple_in_compound();
TestResult test_rtcp_app_integration();
TestResult test_capi_connectivity();
TestResult test_capi_track();
TestResult test_websocketserver();
TestResult test_capi_websocketserver();

static const std::map<std::string, std::function<TestResult()>> tests = {
    {"connectivity", test_connectivity},
    {"connectivity_fail_on_wrong_fingerprint", test_connectivity_fail_on_wrong_fingerprint},
    {"dtls_startup_after_remote_description", test_dtls_startup_after_remote_description},
    {"pem", test_pem},
    {"negotiated", test_negotiated},
    {"reliability", test_reliability},
    {"simulcast_sdp_generation", test_simulcast_sdp_generation},
    {"simulcast_sdp_parsing", test_simulcast_sdp_parsing},
    {"track", test_track},
    {"video_layers_allocation", test_video_layers_allocation},
    {"fir_sdp", test_fir_sdp},
    {"fir_offer_yes_answer_yes", test_fir_offer_yes_answer_yes},
    {"rtx_attribute", test_rtx_attribute},
    {"rtx_description_addrtx", test_rtx_description_addrtx},
    {"rtx_description_addrtx_no_audio", test_rtx_description_addrtx_no_audio},
    {"rtx_dropped_packet", test_rtx_dropped_packet},
    {"rtx_multi_codec", test_rtx_multi_codec},
    {"rtcp_app_single_packet", test_rtcp_app_single_packet},
    {"rtcp_app_compound_packet", test_rtcp_app_compound_packet},
    {"rtcp_app_empty_data", test_rtcp_app_empty_data},
    {"rtcp_app_send", test_rtcp_app_send},
    {"rtcp_app_multiple_in_compound", test_rtcp_app_multiple_in_compound},
    {"rtcp_app_integration", test_rtcp_app_integration},
    {"capi_connectivity", test_capi_connectivity},
    {"capi_track", test_capi_track},
    {"websocketserver", test_websocketserver},
    {"capi_websocketserver", test_capi_websocketserver},
};

int main(int argc, char **argv) {
	rtc::SetThreadPoolSize(4);
	int ok = 0, ko = 0;
	for (int i = 1; i < argc; i++) {
		auto it = tests.find(argv[i]);
		if (it == tests.end()) {
			std::cerr << argv[i] << " test failed. Reason: unknown test" << std::endl;
			ko++;
			continue;
		}
		Test t(argv[i], [&]() {
			try {
				return it->second();
			} catch (const std::exception &e) {
				return TestResult(false, e.what());
			}
		});
		(t.run().success ? ok : ko)++;
	}
	bool cleaned = rtc::Cleanup().wait_for(10s) != std::future_status::timeout;
	if (!cleaned) {
		std::cerr << "cleanup test failed. Reason: timeout" << std::endl;
		ko++;
	}
	std::cout << "Succeeded: " << ok << ". Failed: " << ko << "." << std::endl;
	return ko == 0 ? 0 : 1;
}
