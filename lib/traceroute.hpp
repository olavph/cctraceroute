#pragma once

#include "dns.hpp"

#include <memory>
#include <ostream>
#include <string>
#include <string_view>

class TraceRoute {
 public:
  TraceRoute(std::string_view hostname, int max_hops, std::string_view message,
             std::unique_ptr<DnsResolver> resolver)
      : hostname_(hostname), max_hops_(max_hops), message_(message), resolver_(std::move(resolver)) {}

  void run(std::ostream& out) {
    std::string resolved_ip = resolver_->resolve(hostname_);
    out << "traceroute to " << hostname_ << " (" << resolved_ip << "), " << max_hops_ << " hops max, "
        << message_.size() << " byte packets" << std::endl;
  }

 private:
  std::string hostname_;
  int max_hops_;
  std::string message_;
  std::unique_ptr<DnsResolver> resolver_;
};
