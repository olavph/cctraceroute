#include "dns.hpp"

#include <gtest/gtest.h>

TEST(DNSTest, ResolvesLocalhost) {
  SystemDnsResolver resolver;
  ASSERT_EQ(resolver.resolve("localhost"), "127.0.0.1");
}

TEST(DNSTest, PassesThroughRawIP) {
  SystemDnsResolver resolver;
  ASSERT_EQ(resolver.resolve("8.8.4.4"), "8.8.4.4");
}

TEST(DNSTest, ThrowsOnInvalidHostname) {
  SystemDnsResolver resolver;
  ASSERT_THROW(resolver.resolve("invalid.hostname.zzz"), std::runtime_error);
}

TEST(DNSTest, ReverseResolvesLocalhost) {
  SystemDnsResolver resolver;
  ASSERT_EQ(resolver.reverse_resolve("127.0.0.1"), "localhost");
}

TEST(DNSTest, ReverseResolveReturnsIpWhenNoHostname) {
  SystemDnsResolver resolver;
  std::string result = resolver.reverse_resolve("192.0.2.1");
  ASSERT_EQ(result, "192.0.2.1");
}
