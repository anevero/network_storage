#include "utils.h"

#include <unistd.h>

void SendMessage(int socket_fd, const Message& message) {
  auto string_to_send = message.SerializeAsString();
  ssize_t bytes_sent =
      write(socket_fd, string_to_send.data(), string_to_send.size());
  if (bytes_sent == -1) {
    perror("Error sending the message");
  } else if (bytes_sent < string_to_send.size()) {
    std::cerr << "Sent less bytes than expected."
              << " The message will be corrupted\n";
  }
}
