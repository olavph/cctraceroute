#pragma once

#include <cstdint>
#include <optional>
#include <span>

constexpr std::size_t kMinIpHeaderLen = 20;
constexpr std::size_t kIcmpHeaderLen = 8;
constexpr std::size_t kUdpDestPortOffset = 2;
constexpr std::size_t kUdpHeaderLen = 8;
constexpr std::size_t kIpIhlMask = 0x0F;
constexpr std::size_t kIpIhlScale = 4;
constexpr std::size_t kIpProtocolOffset = 9;
constexpr uint8_t kIpProtocolIcmp = 1;

enum class IcmpType : uint8_t {
  DestUnreachable = 3,
  TimeExceeded = 11,
};

struct IcmpPacket {
  IcmpType type;
  uint16_t original_dest_port;
};

inline std::optional<IcmpPacket> parse_icmp(std::span<const uint8_t> raw_packet) {
  if (raw_packet.size() < kMinIpHeaderLen + kIcmpHeaderLen) {
    return std::nullopt;
  }

  if (raw_packet[kIpProtocolOffset] != kIpProtocolIcmp) {
    return std::nullopt;
  }

  std::size_t outer_ip_len = (raw_packet[0] & kIpIhlMask) * kIpIhlScale;

  if (raw_packet.size() < outer_ip_len + kIcmpHeaderLen) {
    return std::nullopt;
  }

  uint8_t icmp_type = raw_packet[outer_ip_len];

  if (icmp_type != static_cast<uint8_t>(IcmpType::TimeExceeded) &&
      icmp_type != static_cast<uint8_t>(IcmpType::DestUnreachable)) {
    return std::nullopt;
  }

  // Parse the encapsulated original packet: inner IP header + UDP header
  std::size_t inner_ip_offset = outer_ip_len + kIcmpHeaderLen;

  if (raw_packet.size() < inner_ip_offset + kMinIpHeaderLen + kUdpHeaderLen) {
    return std::nullopt;
  }

  std::size_t inner_ip_len = (raw_packet[inner_ip_offset] & kIpIhlMask) * kIpIhlScale;

  if (raw_packet.size() < inner_ip_offset + inner_ip_len + kUdpHeaderLen) {
    return std::nullopt;
  }

  std::size_t udp_offset = inner_ip_offset + inner_ip_len;
  auto dest_port =
      static_cast<uint16_t>((raw_packet[udp_offset + kUdpDestPortOffset] << 8) |
                             raw_packet[udp_offset + kUdpDestPortOffset + 1]);

  return IcmpPacket{static_cast<IcmpType>(icmp_type), dest_port};
}
