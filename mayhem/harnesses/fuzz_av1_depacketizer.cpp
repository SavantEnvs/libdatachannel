// libFuzzer harness: RTP packets from the peer -> AV1RtpDepacketizer (public MediaHandler API).
// Input: [selector byte] then 2-byte length-prefixed RTP/RTCP packets (see fuzz_packets.hpp).
#include "fuzz_packets.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	uint8_t sel = data[0];
	(void)sel;
	std::shared_ptr<rtc::MediaHandler> handler = (sel & 1) ? std::shared_ptr<rtc::MediaHandler>(std::make_shared<rtc::AV1RtpDepacketizer>(rtc::AV1RtpDepacketizer::Packetization::Obu)) : std::shared_ptr<rtc::MediaHandler>(std::make_shared<rtc::AV1RtpDepacketizer>(rtc::AV1RtpDepacketizer::Packetization::TemporalUnit));
	fuzz::feedPackets(handler, data + 1, size - 1);
	return 0;
}
