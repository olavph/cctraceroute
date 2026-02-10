#include "traceroute.hpp"

#include <cxxopts.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

cxxopts::ParseResult parse_cmd(int argc, char** argv) {
  cxxopts::Options options("cctraceroute",
                           "Traceroute is a tool to that allows you to trace the route network "
                           "packets will take from one computer to another over a network.");
  // clang-format off
  options.add_options()
    ("hostname", "Target host name", cxxopts::value<std::string>())
    ("m,maxhops", "Max hops", cxxopts::value<int>()->default_value("64"))
    ("t,text", "Message text", cxxopts::value<std::string>()->default_value("codingchallenges.fyi trace route"))
    ("w,timeout", "Timeout in seconds", cxxopts::value<int>()->default_value("1"))
    ("h,help", "Print help");
  // clang-format on
  options.parse_positional({"hostname"});

  auto result = options.parse(argc, argv);
  if (result.count("help") || !result.count("hostname")) {
    std::cout << options.help() << std::endl;
    exit(0);
  }
  return result;
}

int main(int argc, char** argv) {
  auto result = parse_cmd(argc, argv);
  std::string host_name = result["hostname"].as<std::string>();
  int max_hops = result["maxhops"].as<int>();
  std::string message = result["text"].as<std::string>();
  int timeout = result["timeout"].as<int>();

  TraceRoute traceroute(host_name, max_hops, message, std::make_unique<SystemDnsResolver>(),
                        std::make_unique<NetworkProber>(timeout));
  traceroute.run(std::cout);

  return 0;
}
