#include "connection.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>

#include <arpa/inet.h>
#include <unistd.h>

#include "encryption.h"
#include "message.pb.h"
#include "utils.h"

namespace {

void SendErrorMessage(ErrorInfo::Type error_type,
                      const std::string& description,
                      int socket_fd) {
  ErrorInfo error_info;
  error_info.set_type(error_type);
  error_info.set_description(description);

  Message message_to_send;
  *message_to_send.mutable_error_info() = std::move(error_info);
  SendMessage(socket_fd, message_to_send);
}

void SendOkMessage(const std::string& description,
                   int socket_fd) {
  OkInfo ok_info;
  ok_info.set_description(description);
  Message message_to_send;
  *message_to_send.mutable_ok_info() = std::move(ok_info);
  SendMessage(socket_fd, message_to_send);
}

}  // namespace

Connection::Connection(
    absl::flat_hash_map<std::string, std::unique_ptr<Storage>>* storage,
    int socket_fd) : socket_fd_(socket_fd),
                     storage_(storage) {
  is_closed_future_ = is_closed_.get_future();
  thread_ = std::thread(&Connection::RunEventLoop, this);
}

Connection::~Connection() {
  is_closed_future_.get();
  thread_.join();
}

void Connection::RunEventLoop() {
  const int32_t kBufferSize = 16 * 1024 * 1024;  // 16 megabytes
  auto buffer = std::make_unique<char[]>(kBufferSize);

  while (true) {
    std::memset(buffer.get(), 0, kBufferSize);

    // Receiving new portion of data.
    auto buffer_actual_size = static_cast<int32_t>(read(
        socket_fd_, buffer.get(), kBufferSize));
    if (buffer_actual_size == -1) {
      perror("Error reading from socket");
      continue;
    } else if (buffer_actual_size == 0) {
      // The client initiated shutdown.
      break;
    }

    Message received_message;
    if (!received_message.ParseFromString(
        std::string(buffer.get(), buffer.get() + buffer_actual_size))) {
      SendErrorMessage(ErrorInfo::MESSAGE_CORRUPTED,
                       "Server cannot parse a received message.",
                       socket_fd_);
      continue;
    }

    HandleReceivedMessage(received_message);
  }

  if (shutdown(socket_fd_, SHUT_RDWR) == -1) {
    perror("Error shutting socket down");
  }
  if (close(socket_fd_) == -1) {
    perror("Error closing socket");
  }
  is_closed_.set_value();
}

void Connection::HandleReceivedMessage(const Message& message) {
  if (rsa_public_key_.empty() && !message.has_rsa_public_key()) {
    SendErrorMessage(ErrorInfo::NO_VALID_RSA_PUBLIC_KEY,
                     "Authentication is not completed yet. Server is expecting a message with the RSA public key.",
                     socket_fd_);
    return;
  }

  if (!message.has_rsa_public_key()) {
    int64_t current_time =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (aes_key_expiration_time_ < current_time
        && !message.has_session_key()) {
      SendErrorMessage(ErrorInfo::NO_VALID_SESSION_KEY,
                       "No valid session key found. Server is expecting a message requesting a new session key.",
                       socket_fd_);
      return;
    }
  }

  if (message.has_rsa_public_key()) {
    return HandleRsaKeyMessage(message.rsa_public_key());
  }
  if (message.has_session_key()) {
    return HandleSessionKeyMessage(message.session_key());
  }
  if (message.has_file_operation()) {
    return HandleFileOperationMessage(message.file_operation());
  }

  SendErrorMessage(ErrorInfo::UNEXPECTED_MESSAGE,
                   "Unexpected type of the message",
                   socket_fd_);
}

void Connection::HandleRsaKeyMessage(const RsaPublicKey& rsa_public_key) {
  if (!rsa_public_key_.empty()) {
    SendErrorMessage(ErrorInfo::UNEXPECTED_MESSAGE,
                     "Authentication is already completed. Server is not expecting a message with the RSA key.",
                     socket_fd_);
    return;
  }

  rsa_public_key_ = rsa_public_key.key();
  if (!storage_->contains(rsa_public_key_)) {
    storage_->emplace(rsa_public_key_, std::make_unique<Storage>());
  }

  SendOkMessage("Received RSA public key", socket_fd_);
}

void Connection::HandleSessionKeyMessage(const SessionKey& session_key) {
  aes_encryption_key_ = Generate256BitKey();
  auto encrypted_aes_encryption_key =
      EncryptStringWithRsaPublicKey(aes_encryption_key_, rsa_public_key_);

  int64_t current_time =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  aes_key_expiration_time_ = current_time + 60 * 60;  // 1 hour from now

  SessionKey session_key_proto;
  session_key_proto.set_encryption_key(encrypted_aes_encryption_key);
  session_key_proto.set_expiration_time(aes_key_expiration_time_);

  Message message_to_send;
  *message_to_send.mutable_session_key() = std::move(session_key_proto);
  SendMessage(socket_fd_, message_to_send);
}

void Connection::HandleFileOperationMessage(const FileOperation& file_operation) {
  const auto& client_message_init_vector =
      file_operation.message_encryption_init_vector();
  const auto& client_encrypted_filename = file_operation.filename();
  auto decrypted_filename = DecryptStringWithAesCbcCipher(
      client_encrypted_filename,
      aes_encryption_key_, client_message_init_vector);

  auto operation_type = file_operation.type();

  if (operation_type == FileOperation::GET) {
    auto content =
        storage_->at(rsa_public_key_)->GetFileContents(decrypted_filename);
    if (!content.has_value()) {
      SendErrorMessage(ErrorInfo::FILE_NOT_FOUND,
                       "File with the received name not found. Please create it before querying it.",
                       socket_fd_);
      return;
    }

    auto server_encryption_init_vector = Generate128BitKey();
    auto server_encrypted_filename = EncryptStringWithAesCbcCipher(
        decrypted_filename, aes_encryption_key_, server_encryption_init_vector);
    auto server_encrypted_content = EncryptStringWithAesCbcCipher(
        content.value().content,
        aes_encryption_key_, server_encryption_init_vector);

    FileOperation file_operation_to_send;
    file_operation_to_send.set_filename(server_encrypted_filename);
    file_operation_to_send.set_content(server_encrypted_content);
    file_operation_to_send.set_message_encryption_init_vector(
        server_encryption_init_vector);
    file_operation_to_send.set_content_encryption_init_vector(
        content.value().init_vector);

    Message message_to_send;
    *message_to_send.mutable_file_operation() =
        std::move(file_operation_to_send);
    SendMessage(socket_fd_, message_to_send);
    return;
  }

  if (operation_type == FileOperation::UPDATE) {
    auto decrypted_content = DecryptStringWithAesCbcCipher(
        file_operation.content(),
        aes_encryption_key_, client_message_init_vector);
    storage_->at(rsa_public_key_)->PutFile(
        decrypted_filename, decrypted_content,
        file_operation.content_encryption_init_vector());

    SendOkMessage("Successfully updated the file", socket_fd_);
    return;
  }

  if (operation_type == FileOperation::DELETE) {
    auto status =
        storage_->at(rsa_public_key_)->RemoveFile(decrypted_filename);
    if (!status.ok()) {
      SendErrorMessage(ErrorInfo::FILE_NOT_FOUND,
                       "File with the received name not found. Please create it before querying it.",
                       socket_fd_);
    } else {
      SendOkMessage("Successfully deleted the file", socket_fd_);
    }
    return;
  }
}

bool Connection::IsClosed() const {
  using namespace std::chrono_literals;
  return is_closed_future_.wait_for(0ms) == std::future_status::ready;
}
