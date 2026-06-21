// optisocks5 — sans-IO SOCKS5 codec implementation. See socks5_codec.hpp.
#include "socks5_codec.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstring>
#include <stdexcept>

namespace s5 {
namespace {

void push_port(std::vector<std::uint8_t>& out, std::uint16_t port) {
  out.push_back(static_cast<std::uint8_t>(port >> 8));
  out.push_back(static_cast<std::uint8_t>(port & 0xFF));
}

// host -> (ATYP, raw address bytes). Tries IPv4 then IPv6 literal, else treats
// the string as a domain name (length-prefixed at the call site).
std::uint8_t classify_host(const std::string& host, std::vector<std::uint8_t>& raw) {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    const auto* b = reinterpret_cast<const std::uint8_t*>(&v4.s_addr);
    raw.assign(b, b + 4);
    return kIpv4;
  }
  in6_addr v6{};
  if (::inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    raw.assign(v6.s6_addr, v6.s6_addr + 16);
    return kIpv6;
  }
  raw.assign(host.begin(), host.end());
  return kDomain;
}

}  // namespace

std::uint8_t encode_address(std::vector<std::uint8_t>& out, const Address& a) {
  std::vector<std::uint8_t> raw;
  std::uint8_t atyp = classify_host(a.host, raw);
  if (atyp == kDomain && raw.size() > 255)
    throw std::length_error("domain name exceeds 255 bytes");
  out.push_back(atyp);
  if (atyp == kDomain) out.push_back(static_cast<std::uint8_t>(raw.size()));
  out.insert(out.end(), raw.begin(), raw.end());
  push_port(out, a.port);
  return atyp;
}

std::optional<Address> decode_address(std::span<const std::uint8_t> data,
                                      std::size_t& pos) {
  if (pos >= data.size()) return std::nullopt;
  std::uint8_t atyp = data[pos++];
  Address a;
  if (atyp == kIpv4) {
    if (pos + 4 > data.size()) return std::nullopt;
    char buf[INET_ADDRSTRLEN];
    if (!::inet_ntop(AF_INET, data.data() + pos, buf, sizeof(buf)))
      return std::nullopt;
    a.host = buf;
    pos += 4;
  } else if (atyp == kIpv6) {
    if (pos + 16 > data.size()) return std::nullopt;
    char buf[INET6_ADDRSTRLEN];
    if (!::inet_ntop(AF_INET6, data.data() + pos, buf, sizeof(buf)))
      return std::nullopt;
    a.host = buf;
    pos += 16;
  } else if (atyp == kDomain) {
    if (pos >= data.size()) return std::nullopt;
    std::size_t len = data[pos++];
    if (pos + len > data.size()) return std::nullopt;
    a.host.assign(reinterpret_cast<const char*>(data.data() + pos), len);
    pos += len;
  } else {
    return std::nullopt;  // unknown ATYP
  }
  if (pos + 2 > data.size()) return std::nullopt;
  a.port = static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
  pos += 2;
  return a;
}

// ---- TCP control channel ---------------------------------------------------

std::vector<std::uint8_t> client_greeting(
    std::span<const std::uint8_t> methods) {
  if (methods.size() > 255) throw std::length_error("too many methods (>255)");
  std::vector<std::uint8_t> out;
  out.reserve(2 + methods.size());
  out.push_back(kVer);
  out.push_back(static_cast<std::uint8_t>(methods.size()));
  out.insert(out.end(), methods.begin(), methods.end());
  return out;
}

std::optional<std::uint8_t> parse_method_selection(
    std::span<const std::uint8_t> data) {
  if (data.size() < 2 || data[0] != kVer) return std::nullopt;
  return data[1];
}

std::vector<std::uint8_t> userpass_auth(std::string_view user,
                                        std::string_view pass) {
  if (user.size() > 255 || pass.size() > 255)
    throw std::length_error("username/password exceeds 255 bytes");
  std::vector<std::uint8_t> out;
  out.reserve(3 + user.size() + pass.size());
  out.push_back(kAuthVer);
  out.push_back(static_cast<std::uint8_t>(user.size()));
  out.insert(out.end(), user.begin(), user.end());
  out.push_back(static_cast<std::uint8_t>(pass.size()));
  out.insert(out.end(), pass.begin(), pass.end());
  return out;
}

std::optional<std::uint8_t> parse_auth_reply(
    std::span<const std::uint8_t> data) {
  if (data.size() < 2 || data[0] != kAuthVer) return std::nullopt;
  return data[1];
}

std::vector<std::uint8_t> request(std::uint8_t cmd, const Address& dst) {
  std::vector<std::uint8_t> out;
  out.push_back(kVer);
  out.push_back(cmd);
  out.push_back(0x00);  // RSV
  encode_address(out, dst);
  return out;
}

std::optional<Reply> parse_reply(std::span<const std::uint8_t> data) {
  if (data.size() < 4 || data[0] != kVer) return std::nullopt;
  Reply r;
  r.rep = data[1];
  // data[2] = RSV
  std::size_t pos = 3;
  auto a = decode_address(data, pos);
  if (!a) return std::nullopt;
  r.bound = *a;
  return r;
}

// ---- TCP control channel, SERVER side --------------------------------------

std::optional<std::vector<std::uint8_t>> parse_greeting(
    std::span<const std::uint8_t> data) {
  if (data.size() < 2 || data[0] != kVer) return std::nullopt;
  std::size_t n = data[1];
  if (data.size() < 2 + n) return std::nullopt;
  return std::vector<std::uint8_t>(data.begin() + 2, data.begin() + 2 + n);
}

std::vector<std::uint8_t> method_selection(std::uint8_t method) {
  return {kVer, method};
}

std::optional<UserPass> parse_userpass(std::span<const std::uint8_t> data) {
  if (data.size() < 2 || data[0] != kAuthVer) return std::nullopt;
  std::size_t pos = 1;
  std::size_t ulen = data[pos++];
  if (pos + ulen + 1 > data.size()) return std::nullopt;
  UserPass up;
  up.user.assign(reinterpret_cast<const char*>(data.data() + pos), ulen);
  pos += ulen;
  std::size_t plen = data[pos++];
  if (pos + plen > data.size()) return std::nullopt;
  up.pass.assign(reinterpret_cast<const char*>(data.data() + pos), plen);
  return up;
}

std::vector<std::uint8_t> auth_reply(std::uint8_t status) {
  return {kAuthVer, status};
}

std::optional<Request> parse_request(std::span<const std::uint8_t> data) {
  if (data.size() < 4 || data[0] != kVer) return std::nullopt;
  Request req;
  req.cmd = data[1];
  // data[2] = RSV
  std::size_t pos = 3;
  auto a = decode_address(data, pos);
  if (!a) return std::nullopt;
  req.dst = *a;
  return req;
}

std::vector<std::uint8_t> reply(std::uint8_t rep, const Address& bound) {
  std::vector<std::uint8_t> out;
  out.push_back(kVer);
  out.push_back(rep);
  out.push_back(0x00);  // RSV
  encode_address(out, bound);
  return out;
}

// ---- UDP data channel ------------------------------------------------------

std::vector<std::uint8_t> udp_encapsulate(const Address& dst,
                                          std::span<const std::uint8_t> payload,
                                          std::uint8_t frag) {
  std::vector<std::uint8_t> out;
  out.push_back(0x00);  // RSV
  out.push_back(0x00);  // RSV
  out.push_back(frag);
  encode_address(out, dst);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::optional<UdpDatagram> udp_decapsulate(std::span<const std::uint8_t> data) {
  if (data.size() < 4) return std::nullopt;  // RSV RSV FRAG + at least ATYP
  UdpDatagram d;
  d.frag = data[2];
  std::size_t pos = 3;
  auto a = decode_address(data, pos);
  if (!a) return std::nullopt;
  d.origin = *a;
  d.payload.assign(data.begin() + static_cast<std::ptrdiff_t>(pos), data.end());
  return d;
}

}  // namespace s5
