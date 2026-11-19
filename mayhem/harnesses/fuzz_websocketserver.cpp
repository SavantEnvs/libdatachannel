// libFuzzer harness: bytes from a remote WebSocket client -> rtc::WebSocketServer
// (HTTP upgrade request parsing in wshandshake/http, then WebSocket frame parsing,
// fragmentation, ping/close handling in WsTransport), over a real loopback TCP socket.
//
// One plain (non-TLS) server is started on 127.0.0.1 with an ephemeral port, once, in
// LLVMFuzzerInitialize; it is stateless between connections (each connection gets its own
// transports). Per input: connect, send the bytes, half-close (SHUT_WR) and read until the
// server closes the connection, so every input is fully processed before the next one.
// Input: [flags byte] then payload. flags bit0 = 0: a fixed valid Upgrade request is sent
// first and the payload is WebSocket frames; bit0 = 1: the payload is the whole stream,
// handshake included.
#include "rtc/rtc.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static std::unique_ptr<rtc::WebSocketServer> server;
static std::mutex clientsMutex;
static std::vector<std::shared_ptr<rtc::WebSocket>> clients;

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
	rtc::WebSocketServer::Configuration config;
	config.port = 0;
	config.bindAddress = "127.0.0.1";
	server = std::make_unique<rtc::WebSocketServer>(config);
	server->onClient([](std::shared_ptr<rtc::WebSocket> ws) {
		ws->onMessage([](rtc::message_variant) {});
		std::lock_guard<std::mutex> lock(clientsMutex);
		clients.push_back(std::move(ws));
	});
	return 0;
}

static bool sendAll(int fd, const uint8_t *p, size_t n) {
	while (n > 0) {
		ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
		if (r <= 0)
			return false;
		p += r;
		n -= size_t(r);
	}
	return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1 || !server)
		return 0;
	{
		// Drop the server-side objects of the previous connection (already closed).
		std::lock_guard<std::mutex> lock(clientsMutex);
		clients.clear();
	}
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server->port());
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
		close(fd);
		return 0;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	bool ok = true;
	if (!(data[0] & 1)) {
		static const char handshake[] = "GET /fuzz HTTP/1.1\r\n"
		                                "Host: 127.0.0.1\r\n"
		                                "Upgrade: websocket\r\n"
		                                "Connection: Upgrade\r\n"
		                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		                                "Sec-WebSocket-Version: 13\r\n"
		                                "\r\n";
		ok = sendAll(fd, reinterpret_cast<const uint8_t *>(handshake), sizeof(handshake) - 1);
	}
	if (ok)
		sendAll(fd, data + 1, size - 1);
	shutdown(fd, SHUT_WR);
	char buf[4096];
	while (recv(fd, buf, sizeof(buf), 0) > 0) {
	}
	close(fd);
	return 0;
}
