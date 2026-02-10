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

TEST(TracerouteTest, PrintsHeader) {
  std::ostringstream out;
  TraceRoute traceroute("dns.google.com", 64, "codingchallenges.fyi trace route",
                        std::make_unique<StubDnsResolver>("8.8.4.4"));
  traceroute.run(out);
  ASSERT_EQ(out.str(), "traceroute to dns.google.com (8.8.4.4), 64 hops max, 32 byte packets\n");
}
