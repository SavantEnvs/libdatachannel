// Shared helper for the media-handler harnesses: the fuzz input is a sequence of
// packets, each prefixed by a 2-byte big-endian length. Every packet is classified the
// way the library does it (rtc::IsRtcp) and pushed through the handler chain's public
// incomingChain(), exactly as a Track does with packets received from the peer.
#pragma once
#include "rtc/rtc.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>

namespace fuzz {

inline void feedPackets(const std::shared_ptr<rtc::MediaHandler> &handler, const uint8_t *data,
                        size_t size) {
	auto send = [](rtc::message_ptr) {};
	while (size >= 2) {
		size_t len = (size_t(data[0]) << 8) | data[1];
		data += 2;
		size -= 2;
		if (len > size)
			len = size;
		rtc::binary b(reinterpret_cast<const std::byte *>(data),
		              reinterpret_cast<const std::byte *>(data) + len);
		data += len;
		size -= len;
		bool rtcp = rtc::IsRtcp(b);
		rtc::message_vector v{
		    rtc::make_message(std::move(b), rtcp ? rtc::Message::Control : rtc::Message::Binary)};
		try {
			handler->incomingChain(v, send);
		} catch (const std::exception &) {
			// malformed packets may be rejected with an exception by design
		}
	}
}

// A negotiated video media section (H264 + RTX, one SSRC) so handlers that look at the
// negotiated description (RTX mapping, SSRC tables) take their full code paths.
inline rtc::Description::Video videoMedia() {
	rtc::Description::Video v("video", rtc::Description::Direction::SendRecv);
	v.addH264Codec(96);
	v.addRtxCodec(97, 96, 90000);
	v.addSSRC(0x01020304, "cname", "stream", "track");
	return v;
}

} // namespace fuzz
