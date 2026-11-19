// libFuzzer harness: a remote SDP session description -> rtc::Description
// (session/media sections, rtpmap/fmtp, rid/simulcast, extmap, ssrc), then
// regenerate it and parse the regenerated SDP again.
// Input: [type byte] then the SDP text.
#include "rtc/rtc.hpp"
#include <cstdint>
#include <exception>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	static const char *const types[] = {"offer", "answer", "pranswer", "rollback", "unspec"};
	const char *type = types[data[0] % 5];
	std::string sdp(reinterpret_cast<const char *>(data + 1), size - 1);
	try {
		rtc::Description d(sdp, type);
		std::string out = d.generateSdp("\r\n");
		(void)d.generateApplicationSdp("\r\n");
		(void)std::string(d);
		for (int i = 0; i < d.mediaCount(); i++) {
			auto m = d.media(i);
			if (auto *media = std::get_if<rtc::Description::Media *>(&m)) {
				for (int pt : (*media)->payloadTypes())
					(void)(*media)->rtpMap(pt);
				(void)(*media)->getSSRCs();
				(void)(*media)->description();
			}
		}
		(void)d.extractCandidates();
		rtc::Description d2(out, d.type());
		(void)d2.generateSdp("\r\n");
	} catch (const std::exception &) {
		// malformed SDP is rejected with an exception by design
	}
	return 0;
}
