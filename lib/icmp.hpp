#pragma once

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <cstdint>
#include <optional>
#include <span>

enum class IcmpType : uint8_t {
  DestUnreachable = ICMP_DEST_UNREACH,
  TimeExceeded = ICMP_TIME_EXCEEDED,
};

struct IcmpPacket {
  IcmpType type;
  uint16_t original_dest_port;
};

inline std::optional<IcmpPacket> parse_icmp(std::span<const uint8_t> raw_packet) {
  if (raw_packet.size() < sizeof(struct iphdr)) {
    return std::nullopt;
  }

  const auto& outer_ip = *reinterpret_cast<const struct iphdr*>(raw_packet.data());

  if (outer_ip.protocol != IPPROTO_ICMP) {
    return std::nullopt;
  }

  const std::size_t outer_ip_len = outer_ip.ihl * 4;

  if (raw_packet.size() < outer_ip_len + sizeof(struct icmphdr)) {
    return std::nullopt;
  }

  const auto& icmp = *reinterpret_cast<const struct icmphdr*>(raw_packet.data() + outer_ip_len);

  if (icmp.type != ICMP_TIME_EXCEEDED && icmp.type != ICMP_DEST_UNREACH) {
    return std::nullopt;
  }

  // Parse the encapsulated original packet: inner IP header + UDP header
  const std::size_t inner_ip_offset = outer_ip_len + sizeof(struct icmphdr);

  if (raw_packet.size() < inner_ip_offset + sizeof(struct iphdr) + sizeof(struct udphdr)) {
    return std::nullopt;
  }

  const auto& inner_ip = *reinterpret_cast<const struct iphdr*>(raw_packet.data() + inner_ip_offset);
  std::size_t inner_ip_len = inner_ip.ihl * 4;

  if (raw_packet.size() < inner_ip_offset + inner_ip_len + sizeof(struct udphdr)) {
    return std::nullopt;
  }

  const auto& udp = *reinterpret_cast<const struct udphdr*>(raw_packet.data() + inner_ip_offset + inner_ip_len);

  return IcmpPacket{static_cast<IcmpType>(icmp.type), ntohs(udp.dest)};
}
