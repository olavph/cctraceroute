#include <gtest/gtest.h>

#include <map>
#include <sstream>
#include <vector>

#include "traceroute.hpp"

class StubDnsResolver : public DnsResolver {
 public:
  StubDnsResolver(std::string ip, std::map<std::string, std::string> reverse_map)
      : ip_(std::move(ip)), reverse_map_(std::move(reverse_map)) {}

  std::string resolve(std::string_view /*hostname*/) override { return ip_; }

  std::string reverse_resolve(std::string_view ip) override {
    std::string key(ip);
    auto it = reverse_map_.find(key);
    if (it != reverse_map_.end()) {
      return it->second;
    }
    return key;
  }

 private:
  std::string ip_;
  std::map<std::string, std::string> reverse_map_;
};

class StubProber : public Prober {
 public:
  explicit StubProber(std::vector<HopResult> results) : results_(std::move(results)) {}

  HopResult send_probe(std::string_view /*dest_ip*/, int /*port*/, int /*ttl*/, std::string_view /*payload*/) override {
    return results_.at(call_index_++);
  }

  int call_count() const { return call_index_; }

 private:
  std::vector<HopResult> results_;
  int call_index_ = 0;
};

static std::string get_line(const std::string& output, int line_number) {
  std::istringstream stream(output);
  std::string line;
  for (int i = 0; i <= line_number; ++i) {
    if (!std::getline(stream, line)) {
      return {};
    }
  }
  return line;
}

class TracerouteTest : public ::testing::Test {
 protected:
  static constexpr auto kHostname = "dns.google.com";
  static constexpr auto kResolvedIp = "8.8.4.4";
  static constexpr auto kMessage = "codingchallenges.fyi trace route";
  static constexpr int kMaxHops = 64;

  TraceRoute make_traceroute(std::vector<HopResult> hops, int max_hops = kMaxHops) {
    auto prober = std::make_unique<StubProber>(std::move(hops));
    prober_ = prober.get();
    return TraceRoute(kHostname, max_hops, kMessage, std::make_unique<StubDnsResolver>(kResolvedIp, reverse_map_),
                      std::move(prober));
  }

  std::ostringstream out_;
  std::map<std::string, std::string> reverse_map_;
  StubProber* prober_ = nullptr;
};

TEST_F(TracerouteTest, PrintsHeader) {
  auto traceroute = make_traceroute({{"8.8.4.4", true, false}});

  traceroute.run(out_);

  ASSERT_TRUE(out_.str().starts_with("traceroute to dns.google.com (8.8.4.4), 64 hops max, 32 byte packets\n"));
}

TEST_F(TracerouteTest, TracesMultipleHops) {
  reverse_map_ = {{"192.168.68.1", "my-router.local"}, {"8.8.4.4", "dns.google"}};
  auto traceroute = make_traceroute({
      {"192.168.68.1", false, false},
      {"10.0.0.1", false, false},
      {"8.8.4.4", true, false},
  });

  traceroute.run(out_);
  std::string output = out_.str();

  EXPECT_EQ(get_line(output, 1), " 1  my-router.local (192.168.68.1)");
  EXPECT_EQ(get_line(output, 2), " 2  10.0.0.1 (10.0.0.1)");
  EXPECT_EQ(get_line(output, 3), " 3  dns.google (8.8.4.4)");
}

TEST_F(TracerouteTest, HandlesTimeoutMidTrace) {
  auto traceroute = make_traceroute({
      {"192.168.68.1", false, false},
      {"*", false, true},
      {"8.8.4.4", true, false},
  });

  traceroute.run(out_);
  std::string output = out_.str();

  EXPECT_EQ(get_line(output, 2), " 2  *  * *");
  EXPECT_EQ(get_line(output, 3), " 3  8.8.4.4 (8.8.4.4)");
}

TEST_F(TracerouteTest, StopsAtDestination) {
  auto traceroute = make_traceroute({
      {"192.168.68.1", false, false},
      {"8.8.4.4", true, false},
  });

  traceroute.run(out_);

  EXPECT_EQ(prober_->call_count(), 2);
}

TEST_F(TracerouteTest, StopsAtMaxHops) {
  auto traceroute =
      make_traceroute({{"10.0.0.1", false, false}, {"10.0.0.2", false, false}, {"10.0.0.3", false, false}}, 3);

  traceroute.run(out_);
  std::string output = out_.str();

  EXPECT_EQ(prober_->call_count(), 3);
  EXPECT_EQ(get_line(output, 1), " 1  10.0.0.1 (10.0.0.1)");
  EXPECT_EQ(get_line(output, 3), " 3  10.0.0.3 (10.0.0.3)");
}
