// libFuzzer harness: a remote ICE candidate line -> rtc::Candidate (parse, numeric
// address resolution, serialization). Resolution is numeric-only (no DNS).
// Input: [mid byte] then the candidate text.
#include "rtc/rtc.hpp"
#include <cstdint>
#include <exception>
#include <sstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1)
		return 0;
	std::string mid = (data[0] & 1) ? "0" : "";
	std::string s(reinterpret_cast<const char *>(data + 1), size - 1);
	try {
		rtc::Candidate c(s, mid);
		(void)c.type();
		(void)c.transportType();
		(void)c.priority();
		(void)c.resolve(rtc::Candidate::ResolveMode::Simple); // numeric host only, no DNS
		(void)c.family();
		(void)c.mid();
		(void)c.isResolved();
		(void)c.address();
		(void)c.port();
		std::ostringstream o;
		o << c;
		(void)std::string(c);
		(void)c.candidate();
		rtc::Candidate c2(c.candidate(), mid);
		(void)(c == c2);
	} catch (const std::exception &) {
		// malformed candidates are rejected with an exception by design
	}
	return 0;
}
