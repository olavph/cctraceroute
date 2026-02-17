#include <gtest/gtest.h>

#include <vector>

#include "icmp.hpp"

// Builds a full ICMP response packet:
// [outer IP (20 bytes)][ICMP header (8 bytes)][inner IP (20 bytes)][UDP header (8 bytes)]
// Total: 56 bytes minimum
static std::vector<uint8_t> make_icmp_packet(uint8_t icmp_type, uint16_t dest_port, uint8_t icmp_code = 0) {
  std::vector<uint8_t> packet(
      sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct udphdr), 0);

  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->version = 4;
  outer_ip->ihl = 5;
  outer_ip->protocol = IPPROTO_ICMP;

  auto* icmp = reinterpret_cast<struct icmphdr*>(packet.data() + sizeof(struct iphdr));
  icmp->type = icmp_type;
  icmp->code = icmp_code;

  auto* inner_ip = reinterpret_cast<struct iphdr*>(packet.data() + sizeof(struct iphdr) + sizeof(struct icmphdr));
  inner_ip->version = 4;
  inner_ip->ihl = 5;

  auto* udp = reinterpret_cast<struct udphdr*>(packet.data() + sizeof(struct iphdr) + sizeof(struct icmphdr) +
                                               sizeof(struct iphdr));
  udp->dest = htons(dest_port);

  return packet;
}

TEST(IcmpParseTest, ParsesTimeExceeded) {
  auto packet = make_icmp_packet(ICMP_TIME_EXCEEDED, 33434);
  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::TimeExceeded);
  EXPECT_EQ(result->original_dest_port, 33434);
}

TEST(IcmpParseTest, ParsesDestUnreachable) {
  auto packet = make_icmp_packet(ICMP_DEST_UNREACH, 33435, 3);
  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::DestUnreachable);
  EXPECT_EQ(result->original_dest_port, 33435);
}

TEST(IcmpParseTest, ReturnsNulloptForUnknownType) {
  auto packet = make_icmp_packet(ICMP_ECHO, 33434);
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
  constexpr std::size_t extended_ip_len = 24;
  std::vector<uint8_t> packet(extended_ip_len + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
                              0);

  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->version = 4;
  outer_ip->ihl = 6;
  outer_ip->protocol = IPPROTO_ICMP;

  auto* icmp = reinterpret_cast<struct icmphdr*>(packet.data() + extended_ip_len);
  icmp->type = ICMP_TIME_EXCEEDED;

  auto* inner_ip = reinterpret_cast<struct iphdr*>(packet.data() + extended_ip_len + sizeof(struct icmphdr));
  inner_ip->version = 4;
  inner_ip->ihl = 5;

  auto* udp =
      reinterpret_cast<struct udphdr*>(packet.data() + extended_ip_len + sizeof(struct icmphdr) + sizeof(struct iphdr));
  udp->dest = htons(33434);

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, IcmpType::TimeExceeded);
  EXPECT_EQ(result->original_dest_port, 33434);
}

TEST(IcmpParseTest, ReturnsNulloptWhenPacketTooShortForEncapsulatedUdp) {
  // Outer IP (20) + ICMP header (8) + inner IP (20) = 48, but need 56 for UDP
  std::vector<uint8_t> packet(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr), 0);

  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->version = 4;
  outer_ip->ihl = 5;
  outer_ip->protocol = IPPROTO_ICMP;

  auto* icmp = reinterpret_cast<struct icmphdr*>(packet.data() + sizeof(struct iphdr));
  icmp->type = ICMP_TIME_EXCEEDED;

  auto* inner_ip = reinterpret_cast<struct iphdr*>(packet.data() + sizeof(struct iphdr) + sizeof(struct icmphdr));
  inner_ip->version = 4;
  inner_ip->ihl = 5;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForIncompleteIpHeader) {
  // 19 bytes: one byte short of a full outer IP header
  std::vector<uint8_t> packet(sizeof(struct iphdr) - 1, 0);
  packet[0] = 0x45;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForIncompleteIcmpHeader) {
  // Valid outer IP header but only 4 of 8 ICMP bytes
  std::vector<uint8_t> packet(sizeof(struct iphdr) + 4, 0);

  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->version = 4;
  outer_ip->ihl = 5;
  outer_ip->protocol = IPPROTO_ICMP;

  // Partial ICMP: only type and code, no full header
  packet[sizeof(struct iphdr)] = ICMP_TIME_EXCEEDED;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForIncompleteInnerIpHeader) {
  // Valid outer IP + full ICMP, but inner IP is truncated (only 10 of 20 bytes)
  std::vector<uint8_t> packet(sizeof(struct iphdr) + sizeof(struct icmphdr) + 10, 0);

  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->version = 4;
  outer_ip->ihl = 5;
  outer_ip->protocol = IPPROTO_ICMP;

  auto* icmp = reinterpret_cast<struct icmphdr*>(packet.data() + sizeof(struct iphdr));
  icmp->type = ICMP_TIME_EXCEEDED;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}

TEST(IcmpParseTest, ReturnsNulloptForNonIcmpProtocol) {
  auto packet = make_icmp_packet(ICMP_TIME_EXCEEDED, 33434);
  auto* outer_ip = reinterpret_cast<struct iphdr*>(packet.data());
  outer_ip->protocol = IPPROTO_TCP;

  auto result = parse_icmp(std::span<const uint8_t>(packet));

  EXPECT_FALSE(result.has_value());
}
