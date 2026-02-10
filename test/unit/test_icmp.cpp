#include "icmp.hpp"

#include <gtest/gtest.h>

#include <vector>

static std::vector<uint8_t> make_icmp_packet(uint8_t icmp_type, uint8_t icmp_code = 0) {
  std::vector<uint8_t> packet(kMinIpHeaderLen + kIcmpHeaderLen, 0);
  packet[0] = 0x45;                  // IPv4, IHL=5 (20 bytes)
  packet[kIpProtocolOffset] = kIpProtocolIcmp;
  packet[kMinIpHeaderLen] = icmp_type;
  packet[kMinIpHeaderLen + 1] = icmp_code;
  return packet;
}

TEST(IcmpParseTest, ParsesTimeExceeded) {
  auto packet = make_icmp_packet(11);
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, IcmpResult::TimeExceeded);
}

TEST(IcmpParseTest, ParsesDestUnreachable) {
  auto packet = make_icmp_packet(3, 3);
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, IcmpResult::DestUnreachable);
}

TEST(IcmpParseTest, ReturnsNulloptForUnknownType) {
  auto packet = make_icmp_packet(8);
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForTooShortPacket) {
  std::vector<uint8_t> short_packet(10, 0);
  auto result = parse_icmp(std::span<const uint8_t>(short_packet));
  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, HandlesExtendedIpHeader) {
  std::vector<uint8_t> packet(32, 0);
  packet[0] = 0x46;  // IHL=6 (24 bytes)
  packet[kIpProtocolOffset] = kIpProtocolIcmp;
  packet[24] = 11;   // Time Exceeded at offset 24
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, IcmpResult::TimeExceeded);
}

TEST(IcmpParseTest, ReturnsNulloptWhenPacketTooShortForExtendedHeader) {
  std::vector<uint8_t> packet(28, 0);
  packet[0] = 0x46;  // IHL=6 needs 24+8=32 bytes, but only 28 provided
  packet[kIpProtocolOffset] = kIpProtocolIcmp;
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForNonIcmpProtocol) {
  std::vector<uint8_t> packet(kMinIpHeaderLen + kIcmpHeaderLen, 0);
  packet[0] = 0x45;
  packet[kIpProtocolOffset] = 6;  // TCP, not ICMP
  packet[kMinIpHeaderLen] = 11;   // Would be TimeExceeded if ICMP
  auto result = parse_icmp(std::span<const uint8_t>(packet));
  EXPECT_FALSE(result.has_value());
}
