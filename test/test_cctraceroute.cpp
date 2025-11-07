#include "socket.hpp"

#include <gtest/gtest.h>

TEST(TracerouteTest, SendRecv) {
  UDPSender sender("127.0.0.1", 12345);
  UDPReceiver receiver("127.0.0.1", 12345);

  std::string message = "Hello, UDP!";
  sender.send_packet(message);

  std::array<char, 1024> buffer{};
  ssize_t received = receiver.receive_packet(std::span<char>{buffer});
  ASSERT_GT(received, 0);
  ASSERT_STREQ(buffer.data(), message.c_str());
}
