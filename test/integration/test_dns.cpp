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
