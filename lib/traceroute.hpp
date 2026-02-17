#pragma once

#include <memory>
#include <ostream>
#include <string>
#include <string_view>

#include "dns.hpp"
#include "prober.hpp"

class TraceRoute {
 public:
  TraceRoute(std::string_view hostname, int max_hops, std::string_view message, std::unique_ptr<DnsResolver> resolver,
             std::unique_ptr<Prober> prober)
      : hostname_(hostname),
        max_hops_(max_hops),
        message_(message),
        resolver_(std::move(resolver)),
        prober_(std::move(prober)) {}

  void run(std::ostream& out) {
    std::string resolved_ip = resolver_->resolve(hostname_);
    out << "traceroute to " << hostname_ << " (" << resolved_ip << "), " << max_hops_ << " hops max, "
        << message_.size() << " byte packets" << std::endl;

    constexpr int start_port = 33434;
    for (int ttl = 1; ttl <= max_hops_; ++ttl) {
      HopResult result = prober_->send_probe(resolved_ip, start_port + ttl - 1, ttl, message_);
      print_hop(out, ttl, result);

      if (result.reached_destination) {
        break;
      }
    }
  }

 private:
  void print_hop(std::ostream& out, int ttl, const HopResult& result) {
    if (result.timed_out) {
      out << " " << ttl << "  *  * *" << std::endl;
    } else {
      std::string hostname = resolver_->reverse_resolve(result.sender_ip);
      out << " " << ttl << "  " << hostname << " (" << result.sender_ip << ")" << std::endl;
    }
  }

  std::string hostname_;
  int max_hops_;
  std::string message_;
  std::unique_ptr<DnsResolver> resolver_;
  std::unique_ptr<Prober> prober_;
};
