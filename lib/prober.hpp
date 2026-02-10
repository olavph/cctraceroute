#pragma once

#include "icmp.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>

struct HopResult {
  std::string sender_ip;
  bool reached_destination;
  bool timed_out;
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
    struct sockaddr_in dest_addr {};
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
  explicit IcmpReceiver(int timeout_sec = 5) {
    fd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd_ < 0) {
      throw std::runtime_error("Failed to create ICMP socket (need root/CAP_NET_RAW)");
    }
    struct timeval tv {};
    tv.tv_sec = timeout_sec;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  ~IcmpReceiver() { close(fd_); }

  IcmpReceiver(const IcmpReceiver&) = delete;
  IcmpReceiver& operator=(const IcmpReceiver&) = delete;

  std::optional<IcmpResponse> receive() {
    std::array<uint8_t, 1500> buffer {};
    struct sockaddr_in from_addr {};
    socklen_t from_len = sizeof(from_addr);

    ssize_t bytes =
        recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);

    if (bytes < 0) {
      return std::nullopt;
    }

    char ip_str[INET_ADDRSTRLEN] {};
    inet_ntop(AF_INET, &from_addr.sin_addr, ip_str, sizeof(ip_str));

    auto icmp = parse_icmp(std::span<const uint8_t>(buffer.data(), static_cast<std::size_t>(bytes)));
    return IcmpResponse{std::string(ip_str), icmp};
  }

 private:
  int fd_;
};

class NetworkProber : public Prober {
 public:
  explicit NetworkProber(int timeout_sec = 1) : timeout_sec_(timeout_sec) {}

  HopResult send_probe(std::string_view dest_ip, int port, int ttl, std::string_view payload) override final {
    IcmpReceiver receiver(timeout_sec_);
    UdpSender sender(ttl);
    sender.send(dest_ip, port, payload);

    while (true) {
      auto response = receiver.receive();
      if (!response) {
        return HopResult{"*", false, true};
      }

      if (!response->icmp || response->icmp->original_dest_port != static_cast<uint16_t>(port)) {
        continue;
      }

      bool reached = response->icmp->type == IcmpType::DestUnreachable;
      return HopResult{std::move(response->sender_ip), reached, false};
    }
  }

 private:
  int timeout_sec_;
};
