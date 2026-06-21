// optisocks5 — sans-IO SOCKS5 codec.
//
// Pure, event-loop-agnostic byte builders/parsers for SOCKS5 (RFC 1928) and its
// username/password auth sub-negotiation (RFC 1929). This unit owns NO sockets,
// NO clock, NO event loop: every function turns structs into wire bytes or wire
// bytes into structs. The transport (blocking sockets, epoll, asyncio) lives in
// the caller, so the same codec drives a synchronous client and an async one.
//
// Two message families:
//   * the TCP control channel — greeting, method selection, userpass auth,
//     CONNECT/BIND/UDP-ASSOCIATE request, reply;
//   * the UDP data channel — RFC 1928 §7 [RSV][FRAG][ATYP][ADDR][PORT][DATA].
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace s5 {

// ---- protocol constants ----------------------------------------------------
inline constexpr std::uint8_t kVer = 0x05;        // SOCKS version
inline constexpr std::uint8_t kAuthVer = 0x01;    // RFC 1929 userpass version

enum Cmd : std::uint8_t { kConnect = 0x01, kBind = 0x02, kUdpAssociate = 0x03 };

enum Method : std::uint8_t {
  kNoAuth = 0x00,
  kGssApi = 0x01,
  kUserPass = 0x02,
  kNoAcceptable = 0xFF,
};

enum Atyp : std::uint8_t { kIpv4 = 0x01, kDomain = 0x03, kIpv6 = 0x04 };

// REP codes (RFC 1928 §6); 0x00 = succeeded.
enum Rep : std::uint8_t {
  kSucceeded = 0x00,
  kGeneralFailure = 0x01,
  kNotAllowed = 0x02,
  kNetUnreachable = 0x03,
  kHostUnreachable = 0x04,
  kConnRefused = 0x05,
  kTtlExpired = 0x06,
  kCmdNotSupported = 0x07,
  kAtypNotSupported = 0x08,
};

// An address as it appears on the wire: a literal IPv4/IPv6 or a domain name,
// plus a port. `host` is the textual form; the ATYP is derived from it.
struct Address {
  std::string host;
  std::uint16_t port = 0;
};

// ---- TCP control channel ---------------------------------------------------

// Client greeting: VER NMETHODS METHODS...  (offered auth methods).
std::vector<std::uint8_t> client_greeting(std::span<const std::uint8_t> methods);

// Parse the server's method selection (VER METHOD). nullopt if malformed.
std::optional<std::uint8_t> parse_method_selection(
    std::span<const std::uint8_t> data);

// RFC 1929 userpass request: VER ULEN UNAME PLEN PASSWD.
std::vector<std::uint8_t> userpass_auth(std::string_view user,
                                        std::string_view pass);

// Parse the userpass reply (VER STATUS). Returns STATUS (0 = success).
std::optional<std::uint8_t> parse_auth_reply(std::span<const std::uint8_t> data);

// Request: VER CMD RSV(0) ATYP DST.ADDR DST.PORT. ATYP is chosen from dst.host.
std::vector<std::uint8_t> request(std::uint8_t cmd, const Address& dst);

struct Reply {
  std::uint8_t rep = 0;   // REP code; 0 = succeeded
  Address bound;          // BND.ADDR / BND.PORT
};

// Parse a server reply: VER REP RSV ATYP BND.ADDR BND.PORT. nullopt if truncated.
std::optional<Reply> parse_reply(std::span<const std::uint8_t> data);

// ---- TCP control channel, SERVER side (mirror of the client builders) ------

// Parse a client greeting (VER NMETHODS METHODS...). Returns the offered method
// bytes; nullopt if malformed/truncated (caller may wait for more bytes).
std::optional<std::vector<std::uint8_t>> parse_greeting(
    std::span<const std::uint8_t> data);

// Build the method selection (VER METHOD) a server sends back.
std::vector<std::uint8_t> method_selection(std::uint8_t method);

struct UserPass {
  std::string user;
  std::string pass;
};

// Parse an RFC 1929 userpass request (VER ULEN UNAME PLEN PASSWD).
std::optional<UserPass> parse_userpass(std::span<const std::uint8_t> data);

// Build the userpass reply (VER STATUS); 0 = success.
std::vector<std::uint8_t> auth_reply(std::uint8_t status);

struct Request {
  std::uint8_t cmd = 0;   // CONNECT / BIND / UDP-ASSOCIATE
  Address dst;            // DST.ADDR / DST.PORT
};

// Parse a client request (VER CMD RSV ATYP DST.ADDR DST.PORT). nullopt if short.
std::optional<Request> parse_request(std::span<const std::uint8_t> data);

// Build a server reply (VER REP RSV ATYP BND.ADDR BND.PORT).
std::vector<std::uint8_t> reply(std::uint8_t rep, const Address& bound);

// ---- UDP data channel (RFC 1928 §7) ---------------------------------------

// Wrap `payload` for `dst`: RSV(2) FRAG ATYP DST.ADDR DST.PORT DATA.
std::vector<std::uint8_t> udp_encapsulate(const Address& dst,
                                          std::span<const std::uint8_t> payload,
                                          std::uint8_t frag = 0);

struct UdpDatagram {
  std::uint8_t frag = 0;
  Address origin;                       // the DST.ADDR/PORT field = remote peer
  std::vector<std::uint8_t> payload;    // unwrapped DATA
};

// Parse a UDP relay datagram. nullopt if malformed/truncated.
std::optional<UdpDatagram> udp_decapsulate(std::span<const std::uint8_t> data);

// ---- address codec (exposed for reuse/testing) -----------------------------

// Append [ATYP][ADDR][PORT] for `a` to `out`. Returns the chosen ATYP.
std::uint8_t encode_address(std::vector<std::uint8_t>& out, const Address& a);

// Decode [ATYP][ADDR][PORT] starting at data[pos]. On success returns the
// address and advances `pos` past the port; nullopt if truncated/unknown ATYP.
std::optional<Address> decode_address(std::span<const std::uint8_t> data,
                                      std::size_t& pos);

}  // namespace s5
