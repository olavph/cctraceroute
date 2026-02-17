#pragma once

#include <iomanip>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>

#include "dns.hpp"
#include "prober.hpp"

class TraceRoute {
 public:
  TraceRoute(std::string_view hostname, int max_hops, int tries_per_hop, std::string_view message,
             std::unique_ptr<DnsResolver> resolver, std::unique_ptr<Prober> prober)
      : hostname_(hostname),
        max_hops_(max_hops),
        tries_per_hop_(tries_per_hop),
        message_(message),
        resolver_(std::move(resolver)),
        prober_(std::move(prober)) {}

  void run(std::ostream& out) {
    std::string resolved_ip = resolver_->resolve(hostname_);
    out << "traceroute to " << hostname_ << " (" << resolved_ip << "), " << max_hops_ << " hops max, "
        << message_.size() << " byte packets" << std::endl;

    constexpr int start_port = 33434;
    for (int ttl = 1; ttl <= max_hops_; ++ttl) {
      auto hop = probe_hop(resolved_ip, start_port + (ttl - 1) * tries_per_hop_, ttl);
      print_hop(out, ttl, hop);

      if (hop.reached_destination) {
        break;
      }
    }
  }

 private:
  HopResult probe_hop(const std::string& dest_ip, int base_port, int ttl) {
    double total_rtt = 0.0;
    int success_count = 0;
    std::string sender_ip;
    bool reached = false;

    for (int t = 0; t < tries_per_hop_; ++t) {
      HopResult result = prober_->send_probe(dest_ip, base_port + t, ttl, message_);

      if (result.timed_out) {
        continue;
      }

      total_rtt += result.rtt_ms;
      ++success_count;
      if (sender_ip.empty()) {
        sender_ip = std::move(result.sender_ip);
      }
      if (result.reached_destination) {
        reached = true;
      }
    }

    if (success_count == 0) {
      return HopResult::timed_out_hop();
    }
    double avg_rtt = total_rtt / success_count;
    if (reached) {
      return HopResult::reached(std::move(sender_ip), avg_rtt);
    }
    return HopResult::transit(std::move(sender_ip), avg_rtt);
  }

  void print_hop(std::ostream& out, int ttl, const HopResult& result) {
    if (result.timed_out) {
      out << " " << ttl << "  *  * *" << std::endl;
    } else {
      std::string hostname = resolver_->reverse_resolve(result.sender_ip);
      out << " " << ttl << "  " << hostname << " (" << result.sender_ip << ") " << std::fixed << std::setprecision(3)
          << result.rtt_ms << " ms" << std::endl;
    }
  }

  std::string hostname_;
  int max_hops_;
  int tries_per_hop_;
  std::string message_;
  std::unique_ptr<DnsResolver> resolver_;
  std::unique_ptr<Prober> prober_;
};
