#include "utils.h"

#include <unistd.h>

void SendMessage(int socket_fd, const Message& message) {
  auto string_to_send = message.SerializeAsString();
  ssize_t bytes_sent =
      write(socket_fd, string_to_send.data(), string_to_send.size());
  auto string_size = static_cast<ssize_t>(string_to_send.length());
  if (bytes_sent == -1) {
    perror("Error sending the message");
  } else if (bytes_sent < string_size) {
    std::cerr << "Sent less bytes than expected."
              << " The message will be corrupted\n";
  }
}

std::string RequestStringInput(absl::string_view prompt) {
  std::cout << prompt << "\n: ";
  std::cout.flush();
  std::string input;
  while (input.empty()) {
    std::getline(std::cin, input, '\n');
  }
  return input;
}
