// libFuzzer harness: RTP/RTCP packets from the peer -> RtcpReceivingSession
// (RTCP SR/RR/SDES/REMB/BYE parsing, RTP receive statistics).
// Input: [flags byte] then 2-byte length-prefixed packets (see fuzz_packets.hpp).
// flags bit0: negotiate a video media section first (enables the RTX/SSRC paths).
#include "fuzz_packets.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	auto session = std::make_shared<rtc::RtcpReceivingSession>();
	if (data[0] & 1)
		session->mediaChain(fuzz::videoMedia());
	fuzz::feedPackets(session, data + 1, size - 1);
	return 0;
}
