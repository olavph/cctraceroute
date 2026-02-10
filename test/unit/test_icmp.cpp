#include "icmp.hpp"

#include <gtest/gtest.h>

#include <vector>

// Builds a full ICMP response packet:
// [outer IP (20 bytes)][ICMP header (8 bytes)][inner IP (20 bytes)][UDP header (8 bytes)]
// Total: 56 bytes minimum
static std::vector<uint8_t> make_icmp_packet(uint8_t icmp_type, uint16_t dest_port, uint8_t icmp_code = 0) {
  std::vector<uint8_t> packet(kMinIpHeaderLen + kIcmpHeaderLen + kMinIpHeaderLen + kUdpHeaderLen, 0);

  // Outer IP header
  packet[0] = 0x45;  // IPv4, IHL=5
  packet[kIpProtocolOffset] = kIpProtocolIcmp;

  // ICMP header at offset 20
  packet[kMinIpHeaderLen] = icmp_type;
  packet[kMinIpHeaderLen + 1] = icmp_code;

  // Inner IP header at offset 28
  std::size_t inner_ip_offset = kMinIpHeaderLen + kIcmpHeaderLen;
  packet[inner_ip_offset] = 0x45;  // IPv4, IHL=5

  // UDP dest port at offset 28 + 20 + 2 = 50 (network byte order)
  std::size_t udp_offset = inner_ip_offset + kMinIpHeaderLen;
  packet[udp_offset + kUdpDestPortOffset] = static_cast<uint8_t>(dest_port >> 8);
  packet[udp_offset + kUdpDestPortOffset + 1] = static_cast<uint8_t>(dest_port & 0xFF);

  return packet;
}

TEST(IcmpParseTest, ParsesTimeExceeded) {
  auto packet = make_icmp_packet(11, 33434);
  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::TimeExceeded);
  EXPECT_EQ(result->original_dest_port, 33434);
}

TEST(IcmpParseTest, ParsesDestUnreachable) {
  auto packet = make_icmp_packet(3, 33435, 3);
  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::DestUnreachable);
  EXPECT_EQ(result->original_dest_port, 33435);
}

TEST(IcmpParseTest, ReturnsNulloptForUnknownType) {
  auto packet = make_icmp_packet(8, 33434);
  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForTooShortPacket) {
  std::vector<uint8_t> short_packet(10, 0);
  auto result = parse_icmp(std::span<const uint8_t>(short_packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, HandlesExtendedOuterIpHeader) {
  // Outer IHL=6 (24 bytes), shifts everything by 4
  std::vector<uint8_t> packet(24 + kIcmpHeaderLen + kMinIpHeaderLen + kUdpHeaderLen, 0);
  packet[0] = 0x46;  // IHL=6
  packet[kIpProtocolOffset] = kIpProtocolIcmp;
  packet[24] = 11;  // ICMP Time Exceeded

  std::size_t inner_ip_offset = 24 + kIcmpHeaderLen;
  packet[inner_ip_offset] = 0x45;

  std::size_t udp_offset = inner_ip_offset + kMinIpHeaderLen;
  packet[udp_offset + kUdpDestPortOffset] = 0x82;  // 33434 = 0x829A
  packet[udp_offset + kUdpDestPortOffset + 1] = 0x9A;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::TimeExceeded);
  EXPECT_EQ(result->original_dest_port, 33434);
}

TEST(IcmpParseTest, ReturnsNulloptWhenPacketTooShortForEncapsulatedUdp) {
  // Outer IP (20) + ICMP header (8) + inner IP (20) = 48, but need 56 for UDP
  std::vector<uint8_t> packet(48, 0);
  packet[0] = 0x45;
  packet[kIpProtocolOffset] = kIpProtocolIcmp;
  packet[kMinIpHeaderLen] = 11;
  packet[kMinIpHeaderLen + kIcmpHeaderLen] = 0x45;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForNonIcmpProtocol) {
  auto packet = make_icmp_packet(11, 33434);
  packet[kIpProtocolOffset] = 6;  // TCP, not ICMP

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}
