// libFuzzer harness: RTP packets from the peer -> H265RtpDepacketizer (public MediaHandler API).
// Input: [selector byte] then 2-byte length-prefixed RTP/RTCP packets (see fuzz_packets.hpp).
#include "fuzz_packets.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	uint8_t sel = data[0];
	(void)sel;
	std::shared_ptr<rtc::MediaHandler> handler = std::make_shared<rtc::H265RtpDepacketizer>(rtc::H265RtpDepacketizer::Separator(1 + sel % 3) /* Length is documented as unimplemented (ctor throws) */);
	fuzz::feedPackets(handler, data + 1, size - 1);
	return 0;
}
