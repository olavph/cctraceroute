#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>

#include "icmp.hpp"

struct HopResult {
  std::string sender_ip;
  bool reached_destination = false;
  bool timed_out = false;
  double rtt_ms = 0.0;

  static HopResult timed_out_hop() { return {.sender_ip = "*", .timed_out = true}; }

  static HopResult reached(std::string ip, double rtt) {
    return {.sender_ip = std::move(ip), .reached_destination = true, .rtt_ms = rtt};
  }

  static HopResult transit(std::string ip, double rtt) { return {.sender_ip = std::move(ip), .rtt_ms = rtt}; }
};

class Prober {
 public:
  virtual ~Prober() = default;
  virtual HopResult send_probe(std::string_view dest_ip, int port, int ttl, std::string_view payload) = 0;
};

class UdpSender {
 public:
  explicit UdpSender(int ttl) {
    fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
      throw std::runtime_error("Failed to create UDP socket");
    }
    if (setsockopt(fd_, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
      close(fd_);
      throw std::runtime_error("Failed to set TTL");
    }
  }

  ~UdpSender() { close(fd_); }

  UdpSender(const UdpSender&) = delete;
  UdpSender& operator=(const UdpSender&) = delete;

  void send(std::string_view dest_ip, int port, std::string_view payload) {
    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(static_cast<uint16_t>(port));
    std::string dest_str(dest_ip);
    inet_pton(AF_INET, dest_str.c_str(), &dest_addr.sin_addr);

    ssize_t sent = sendto(fd_, payload.data(), payload.size(), 0, reinterpret_cast<struct sockaddr*>(&dest_addr),
                          sizeof(dest_addr));
    if (sent < 0) {
      throw std::runtime_error("Failed to send UDP packet");
    }
  }

 private:
  int fd_;
};

struct IcmpResponse {
  std::string sender_ip;
  std::optional<IcmpPacket> icmp;
};

class IcmpReceiver {
 public:
  explicit IcmpReceiver(std::chrono::milliseconds timeout) {
    fd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_ < 0) {
      throw std::runtime_error("Failed to create ICMP socket (need root/CAP_NET_RAW)");
    }

    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    const auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(timeout) - seconds;

    struct timeval tv{};
    tv.tv_sec = seconds.count();
    tv.tv_usec = microseconds.count();
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  ~IcmpReceiver() { close(fd_); }

  IcmpReceiver(const IcmpReceiver&) = delete;
  IcmpReceiver& operator=(const IcmpReceiver&) = delete;

  std::optional<IcmpResponse> receive() {
    std::array<uint8_t, 1500> buffer{};
    struct sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    ssize_t bytes =
        recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);

    if (bytes < 0) {
      return std::nullopt;
    }

    char ip_str[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, sizeof(ip_str));

    auto icmp = parse_icmp(std::span<const uint8_t>(buffer.data(), static_cast<std::size_t>(bytes)));
    return IcmpResponse{.sender_ip = std::string(ip_str), .icmp = icmp};
  }

 private:
  int fd_;
};

class NetworkProber : public Prober {
 public:
  explicit NetworkProber(std::chrono::milliseconds timeout) : timeout_(timeout) {}

  HopResult send_probe(std::string_view dest_ip, int port, int ttl, std::string_view payload) override final {
    IcmpReceiver receiver(timeout_);
    UdpSender sender(ttl);

    auto start = std::chrono::steady_clock::now();
    sender.send(dest_ip, port, payload);

    while (true) {
      auto response = receiver.receive();
      if (!response) {
        return HopResult::timed_out_hop();
      }

      if (!response->icmp || response->icmp->original_dest_port != static_cast<uint16_t>(port)) {
        continue;
      }

      auto end = std::chrono::steady_clock::now();
      double rtt_ms = std::chrono::duration<double, std::milli>(end - start).count();

      if (response->icmp->type == IcmpType::DestUnreachable) {
        return HopResult::reached(std::move(response->sender_ip), rtt_ms);
      }
      return HopResult::transit(std::move(response->sender_ip), rtt_ms);
    }
  }

 private:
  std::chrono::milliseconds timeout_;
};
