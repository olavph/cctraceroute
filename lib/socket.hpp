#pragma once

#include <arpa/inet.h>
#include <unistd.h>

#include <cstring>
#include <span>
#include <stdexcept>
#include <string_view>

class UDPSender {
 public:
  UDPSender(std::string_view host, int port) {
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
      throw std::runtime_error("Failed to create socket");
    }

    // Set port and IP
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.data(), &server_addr.sin_addr) <= 0) {
      throw std::runtime_error("Invalid address");
    }
  }
  ~UDPSender() {
    close(sockfd);
  }

  void send_packet(std::string_view message) {
    ssize_t sent_bytes =
        sendto(sockfd, message.data(), message.size(), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (sent_bytes < 0) {
      throw std::runtime_error("Failed to send packet");
    }
  }

 private:
  int sockfd{0};
  struct sockaddr_in server_addr{};
};

class UDPReceiver {
 public:
  UDPReceiver(std::string_view bind_address, int port) {
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
      throw std::runtime_error("Failed to create socket");
    }

    // Bind to the specified port
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_address.data(), &server_addr.sin_addr) <= 0) {
      throw std::runtime_error("Invalid address");
    }

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      throw std::runtime_error("Bind failed");
    }
  }
  ~UDPReceiver() {
    close(sockfd);
  }

  ssize_t receive_packet(std::span<char> buffer) {
    ssize_t recv_bytes = recvfrom(sockfd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
    if (recv_bytes < 0) {
      throw std::runtime_error("Failed to receive packet");
    }
    return recv_bytes;
  }

 private:
  int sockfd{0};
  struct sockaddr_in server_addr{};
};
