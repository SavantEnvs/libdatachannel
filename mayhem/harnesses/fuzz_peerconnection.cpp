// libFuzzer harness: remote signaling -> PeerConnection through the C API
// (rtcSetRemoteDescription: description validation, track/data channel negotiation,
// local answer generation; rtcAddRemoteCandidate: remote ICE candidates into the agent).
// Input: [type byte] SDP text, then optionally "\n--\n" followed by candidate lines.
// No ICE servers are configured; each input gets a fresh PeerConnection, deleted after.
#include "rtc/rtc.h"
#include <cstdint>
#include <cstring>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	static const char *const types[] = {"offer", "answer", "pranswer", "rollback"};
	const char *type = types[data[0] % 4];
	std::string in(reinterpret_cast<const char *>(data + 1), size - 1);
	std::string sdp = in, cands;
	size_t sep = in.find("\n--\n");
	if (sep != std::string::npos) {
		sdp = in.substr(0, sep);
		cands = in.substr(sep + 4);
	}

	rtcConfiguration config;
	std::memset(&config, 0, sizeof(config));
	config.disableAutoNegotiation = false;
	int pc = rtcCreatePeerConnection(&config);
	if (pc < 0)
		return 0;
	rtcSetRemoteDescription(pc, sdp.c_str(), type);
	size_t pos = 0;
	while (pos < cands.size()) {
		size_t nl = cands.find('\n', pos);
		if (nl == std::string::npos)
			nl = cands.size();
		std::string line = cands.substr(pos, nl - pos);
		pos = nl + 1;
		if (!line.empty())
			rtcAddRemoteCandidate(pc, line.c_str(), nullptr);
	}
	char buf[4096];
	rtcGetLocalDescription(pc, buf, sizeof(buf));
	rtcDeletePeerConnection(pc);
	return 0;
}
