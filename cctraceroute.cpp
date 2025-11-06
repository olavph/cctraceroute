#include <cxxopts.hpp>

#include <iostream>
#include <string>
#include <string_view>

constexpr std::string_view MESSAGE{"codingchallenges.fyi trace route"};

cxxopts::ParseResult parse_cmd(int argc, char** argv) {
  cxxopts::Options options("cctraceroute","Traceroute is a tool to that allows you to trace the route network packets will take from one computer to another over a network.");
  options.add_options()
    ("hostname","Target host name", cxxopts::value<std::string>())
    ("m,maxhops","Max hops", cxxopts::value<int>()->default_value("64"))
    ("h,help", "Print help");
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

  std::cout << "Tracing route to " << host_name << " with max hops " << max_hops << std::endl;

  return 0;
}
