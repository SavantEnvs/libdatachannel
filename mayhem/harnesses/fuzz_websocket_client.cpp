// libFuzzer harness: bytes from a remote WebSocket *server* -> rtc::WebSocket (client side):
// the HTTP 101 upgrade response (WsHandshake::parseHttpResponse -> parseHttpLines /
// parseHttpHeaders), then unmasked server->client WebSocket frames (WsTransport::parseFrame,
// fragmentation, ping/close handling), over a real loopback TCP socket.
//
// A plain TCP listener on 127.0.0.1 (ephemeral port) is opened once in LLVMFuzzerInitialize; it
// holds no per-connection state. Per input: a fresh rtc::WebSocket opens ws://127.0.0.1:<port>/,
// the harness accepts the connection, reads the client's upgrade request, writes the fuzz bytes
// back, half-closes (SHUT_WR), drains the client's side until it closes, and waits for the
// client's onClosed before returning, so every input is fully processed before the next one.
//
// Input: [flags byte] then payload. flags bit0 = 0: the harness first sends a valid
// "101 Switching Protocols" response whose Sec-WebSocket-Accept is computed (RFC 6455, with
// OpenSSL SHA-1) from the random key in the client's request, and the payload is server frames;
// bit0 = 1: the payload is the whole response stream, HTTP status line and headers included.
#include "rtc/rtc.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

static int listenFd = -1;
static uint16_t listenPort = 0;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
	listenFd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenFd < 0)
		return 0;
	int one = 1;
	setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t len = sizeof(addr);
	if (bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
	    listen(listenFd, 1) != 0 ||
	    getsockname(listenFd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
		close(listenFd);
		listenFd = -1;
		return 0;
	}
	listenPort = ntohs(addr.sin_port);
	return 0;
}

static bool sendAll(int fd, const void *buf, size_t n) {
	auto p = static_cast<const uint8_t *>(buf);
	while (n > 0) {
		ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
		if (r <= 0)
			return false;
		p += r;
		n -= size_t(r);
	}
	return true;
}

// RFC 6455 section 4.2.2: base64(SHA-1(key + GUID)).
static std::string acceptKey(const std::string &key) {
	std::string s = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1(reinterpret_cast<const unsigned char *>(s.data()), s.size(), digest);
	unsigned char out[4 * ((SHA_DIGEST_LENGTH + 2) / 3) + 1];
	int n = EVP_EncodeBlock(out, digest, SHA_DIGEST_LENGTH);
	return std::string(reinterpret_cast<char *>(out), size_t(n));
}

// Value of the Sec-WebSocket-Key header in the client's request (empty if absent).
static std::string requestKey(const std::string &req) {
	static const char name[] = "sec-websocket-key:";
	std::string lower(req);
	for (auto &c : lower)
		c = char(tolower(static_cast<unsigned char>(c)));
	size_t pos = lower.find(name);
	if (pos == std::string::npos)
		return "";
	pos += sizeof(name) - 1;
	while (pos < req.size() && req[pos] == ' ')
		++pos;
	size_t end = req.find("\r\n", pos);
	return req.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1 || listenFd < 0)
		return 0;

	auto closed = std::make_shared<std::promise<void>>();
	auto done = closed->get_future();
	auto once = std::make_shared<std::once_flag>();
	auto ws = std::make_unique<rtc::WebSocket>();
	ws->onMessage([](rtc::message_variant) {});
	ws->onError([](std::string) {});
	ws->onClosed([closed, once]() { std::call_once(*once, [&] { closed->set_value(); }); });
	ws->open("ws://127.0.0.1:" + std::to_string(listenPort) + "/fuzz");

	int fd = accept(listenFd, nullptr, nullptr);
	if (fd < 0) {
		ws.reset();
		return 0;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	// Read the client's upgrade request (up to the blank line).
	std::string req;
	char buf[4096];
	while (req.find("\r\n\r\n") == std::string::npos) {
		ssize_t r = recv(fd, buf, sizeof(buf), 0);
		if (r <= 0)
			break;
		req.append(buf, size_t(r));
	}

	bool ok = true;
	if (!(data[0] & 1)) {
		std::string resp = "HTTP/1.1 101 Switching Protocols\r\n"
		                   "Upgrade: websocket\r\n"
		                   "Connection: Upgrade\r\n"
		                   "Sec-WebSocket-Accept: " +
		                   acceptKey(requestKey(req)) + "\r\n\r\n";
		ok = sendAll(fd, resp.data(), resp.size());
	}
	if (ok)
		sendAll(fd, data + 1, size - 1);
	shutdown(fd, SHUT_WR);
	while (recv(fd, buf, sizeof(buf), 0) > 0) {
	}
	close(fd);

	// The client sees EOF (or a protocol error) and closes; wait for it.
	done.wait();
	ws.reset();
	return 0;
}
