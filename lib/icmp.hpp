#pragma once

#include <cstdint>
#include <optional>
#include <span>

constexpr std::size_t kMinIpHeaderLen = 20;
constexpr std::size_t kIcmpHeaderLen = 8;
constexpr std::size_t kIpIhlMask = 0x0F;
constexpr std::size_t kIpIhlScale = 4;
constexpr std::size_t kIpProtocolOffset = 9;
constexpr uint8_t kIpProtocolIcmp = 1;

enum class IcmpResult : uint8_t {
  DestUnreachable = 3,
  TimeExceeded = 11,
};

inline std::optional<IcmpResult> parse_icmp(std::span<const uint8_t> raw_packet) {
  if (raw_packet.size() < kMinIpHeaderLen + kIcmpHeaderLen) {
    return std::nullopt;
  }

  if (raw_packet[kIpProtocolOffset] != kIpProtocolIcmp) {
    return std::nullopt;
  }

  std::size_t ip_header_len = (raw_packet[0] & kIpIhlMask) * kIpIhlScale;

  if (raw_packet.size() < ip_header_len + kIcmpHeaderLen) {
    return std::nullopt;
  }

  uint8_t icmp_type = raw_packet[ip_header_len];

  if (icmp_type == static_cast<uint8_t>(IcmpResult::TimeExceeded) ||
      icmp_type == static_cast<uint8_t>(IcmpResult::DestUnreachable)) {
    return static_cast<IcmpResult>(icmp_type);
  }

  return std::nullopt;
}
