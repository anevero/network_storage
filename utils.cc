#include "utils.h"

#include <chrono>
#include <thread>
#include <unistd.h>

#include "encryption.h"

namespace {

absl::Status SendMessageWrapper(const MessageWrapper& message, int socket_fd) {
  auto string = message.SerializeAsString();
  auto string_size = static_cast<ssize_t>(string.length());

  int retry_count = 1;
  int retry_delay = 2;

  while (retry_count <= kRetriesNumber) {
    ssize_t bytes_sent = write(socket_fd, string.data(), string.length());
    if (bytes_sent == string_size) {
      break;
    }

    if (retry_count == kRetriesNumber) {
      if (bytes_sent == -1) {
        return absl::UnavailableError("Error sending the message");
      } else if (bytes_sent < string_size) {
        return absl::UnavailableError(
            "Sent less bytes than expected. The message will be corrupted");
      }
    }

    std::this_thread::sleep_for(std::chrono::seconds(retry_delay));
    ++retry_count;
    retry_delay *= 2;
  }

  return absl::OkStatus();
}

absl::StatusOr<MessageWrapper> ReceiveMessageWrapper(int socket_fd) {
  constexpr int32_t kBufferSize = 16 * 1024 * 1024;  // 16 megabytes
  static auto buffer = std::make_unique<char[]>(kBufferSize);

  MessageWrapper received_message;
  int retry_count = 1;
  int retry_delay = 2;

  while (retry_count <= kRetriesNumber) {
    std::memset(buffer.get(), 0, kBufferSize);
    ssize_t bytes_received = read(socket_fd, buffer.get(), kBufferSize);

    if (bytes_received > 0) {
      if (received_message.ParseFromString(
          std::string(buffer.get(), buffer.get() + bytes_received))) {
        break;
      }
      if (retry_count == kRetriesNumber) {
        return absl::InternalError("Received message is corrupted");
      }
    } else if (bytes_received == 0) {
      // The receiver has disconnected.
      return absl::CancelledError("The sender has disconnected");
    } else if (bytes_received == -1 && retry_count == kRetriesNumber) {
      return absl::UnavailableError("Error receiving the message");
    }

    std::this_thread::sleep_for(std::chrono::seconds(retry_delay));
    ++retry_count;
    retry_delay *= 2;
  }

  return received_message;
}

}  // namespace

absl::Status SendUnencryptedMessage(const Message& message, int socket_fd) {
  MessageWrapper message_wrapper;
  message_wrapper.set_message(message.SerializeAsString());
  return SendMessageWrapper(message_wrapper, socket_fd);
}

absl::Status EncryptAndSendMessage(const Message& message, int socket_fd,
                                   const std::string& aes_encryption_key) {
  auto message_str = message.SerializeAsString();
  auto init_vector = Generate128BitKey();
  auto encrypted_message_str = EncryptStringWithAesCbcCipher(
      message_str, aes_encryption_key, init_vector);

  MessageWrapper message_wrapper;
  message_wrapper.set_aes_init_vector(init_vector);
  message_wrapper.set_message(encrypted_message_str);

  return SendMessageWrapper(message_wrapper, socket_fd);
}

absl::StatusOr<Message> ReceiveAndDecryptMessage(
    int socket_fd, const std::string& aes_encryption_key) {
  auto message_wrapper = ReceiveMessageWrapper(socket_fd);
  if (!message_wrapper.ok()) {
    return message_wrapper.status();
  }

  auto message_str = message_wrapper->message();
  if (!message_wrapper->aes_init_vector().empty()) {
    message_str = DecryptStringWithAesCbcCipher(
        message_str, aes_encryption_key, message_wrapper->aes_init_vector());
  }

  Message message;
  message.ParseFromString(message_str);

  return message;
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
