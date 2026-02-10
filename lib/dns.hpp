#pragma once

#include <arpa/inet.h>
#include <netdb.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

class DnsResolver {
 public:
  virtual ~DnsResolver() = default;
  virtual std::string resolve(std::string_view hostname) = 0;
  virtual std::string reverse_resolve(std::string_view ip) = 0;
};

class SystemDnsResolver : public DnsResolver {
 public:
  std::string resolve(std::string_view hostname) override final {
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* result = nullptr;
    int status = getaddrinfo(hostname.data(), nullptr, &hints, &result);
    if (status != 0) {
      throw std::runtime_error(std::string("Failed to resolve hostname: ") + gai_strerror(status));
    }

    char ip[INET_ADDRSTRLEN]{};
    auto* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    freeaddrinfo(result);

    return std::string(ip);
  }

  std::string reverse_resolve(std::string_view ip) override final {
    struct sockaddr_in sa {};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.data(), &sa.sin_addr);

    char host[NI_MAXHOST] {};
    int status = getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, 0);
    if (status != 0) {
      return std::string(ip);
    }

    return std::string(host);
  }
};
