#include "traceroute.hpp"

#include <gtest/gtest.h>

#include <sstream>

class StubDnsResolver : public DnsResolver {
 public:
  explicit StubDnsResolver(std::string ip) : ip_(std::move(ip)) {}
  std::string resolve(std::string_view /*hostname*/) override { return ip_; }

 private:
  std::string ip_;
};

class StubProber : public Prober {
 public:
  explicit StubProber(HopResult result) : result_(std::move(result)) {}
  HopResult send_probe(std::string_view /*dest_ip*/, int /*port*/, int /*ttl*/,
                        std::string_view /*payload*/) override {
    return result_;
  }

 private:
  HopResult result_;
};

TEST(TracerouteTest, PrintsHeader) {
  std::ostringstream out;
  TraceRoute traceroute("dns.google.com", 64, "codingchallenges.fyi trace route",
                        std::make_unique<StubDnsResolver>("8.8.4.4"),
                        std::make_unique<StubProber>(HopResult{"192.168.1.1", false, false}));
  traceroute.run(out);
  std::string output = out.str();
  ASSERT_TRUE(output.starts_with("traceroute to dns.google.com (8.8.4.4), 64 hops max, 32 byte packets\n"));
}

TEST(TracerouteTest, PrintsFirstHop) {
  std::ostringstream out;
  TraceRoute traceroute("dns.google.com", 64, "codingchallenges.fyi trace route",
                        std::make_unique<StubDnsResolver>("8.8.4.4"),
                        std::make_unique<StubProber>(HopResult{"192.168.68.1", false, false}));
  traceroute.run(out);
  std::string output = out.str();
  auto second_line_start = output.find('\n') + 1;
  std::string second_line = output.substr(second_line_start);
  if (second_line.ends_with('\n')) {
    second_line.pop_back();
  }
  EXPECT_EQ(second_line, " 1  192.168.68.1");
}

TEST(TracerouteTest, PrintsTimeoutAsAsterisk) {
  std::ostringstream out;
  TraceRoute traceroute("dns.google.com", 64, "codingchallenges.fyi trace route",
                        std::make_unique<StubDnsResolver>("8.8.4.4"),
                        std::make_unique<StubProber>(HopResult{"*", false, true}));
  traceroute.run(out);
  std::string output = out.str();
  auto second_line_start = output.find('\n') + 1;
  std::string second_line = output.substr(second_line_start);
  if (second_line.ends_with('\n')) {
    second_line.pop_back();
  }
  EXPECT_EQ(second_line, " 1  *");
}
