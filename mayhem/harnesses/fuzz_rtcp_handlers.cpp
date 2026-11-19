// libFuzzer harness: RTCP feedback from the peer -> the RTCP handler chain
// RembHandler -> PliHandler -> RtcpAppHandler -> RtcpNackResponder
// (REMB, PLI/FIR, APP and generic NACK parsing).
// Input: [flags byte] then 2-byte length-prefixed packets (see fuzz_packets.hpp).
// flags bit0: negotiate a video media section first. flags bit1: first send a few RTP
// packets outgoing so the NACK responder has stored packets to retransmit.
#include "fuzz_packets.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	uint8_t flags = data[0];
	auto remb = std::make_shared<rtc::RembHandler>([](unsigned int) {});
	remb->addToChain(std::make_shared<rtc::PliHandler>([]() {}));
	remb->addToChain(
	    std::make_shared<rtc::RtcpAppHandler>([](const rtc::RtcpAppName, uint8_t, rtc::binary) {}));
	remb->addToChain(std::make_shared<rtc::RtcpNackResponder>(64));
	if (flags & 1)
		remb->mediaChain(fuzz::videoMedia());
	if (flags & 2) {
		auto send = [](rtc::message_ptr) {};
		for (uint16_t seq = 0; seq < 8; ++seq) {
			rtc::binary pkt(12 + 4, std::byte{0});
			pkt[0] = std::byte{0x80};
			pkt[1] = std::byte{96};
			pkt[2] = std::byte(seq >> 8);
			pkt[3] = std::byte(seq & 0xff);
			pkt[8] = std::byte{0x01};
			pkt[9] = std::byte{0x02};
			pkt[10] = std::byte{0x03};
			pkt[11] = std::byte{0x04};
			rtc::message_vector v{rtc::make_message(std::move(pkt), rtc::Message::Binary)};
			try {
				remb->outgoingChain(v, send);
			} catch (const std::exception &) {
			}
		}
	}
	fuzz::feedPackets(remb, data + 1, size - 1);
	return 0;
}
