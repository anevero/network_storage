#include "connection.h"

#include <chrono>
#include <cstdint>
#include <memory>

#include <arpa/inet.h>
#include <unistd.h>

#include "encryption.h"
#include "message.pb.h"
#include "utils.h"

#include "absl/status/status.h"

namespace {

void SendInfoMessage(Info::Status status,
                     const std::string& description,
                     int socket_fd) {
  Info info;
  info.set_status(status);
  info.set_description(description);

  Message message_to_send;
  *message_to_send.mutable_info() = std::move(info);
  SendUnencryptedMessage(message_to_send, socket_fd).IgnoreError();
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
  while (true) {
    auto received_message = ReceiveAndDecryptMessage(
        socket_fd_, aes_encryption_key_);
    if (!received_message.ok()) {
      if (absl::IsCancelled(received_message.status())) {
        // The client has disconnected.
        break;
      }
      continue;
    }

    HandleReceivedMessage(*received_message);
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
    SendInfoMessage(Info::NO_VALID_RSA_PUBLIC_KEY_ERROR,
                    "Authentication is not completed yet. Server is expecting a message with the RSA public key.",
                    socket_fd_);
    return;
  }

  if (!message.has_rsa_public_key()) {
    int64_t current_time =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (aes_key_expiration_time_ < current_time
        && !message.has_session_key()) {
      SendInfoMessage(Info::NO_VALID_SESSION_KEY_ERROR,
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
  if (message.has_data_operation()) {
    return HandleDataOperationMessage(message.data_operation());
  }

  SendInfoMessage(Info::UNEXPECTED_MESSAGE_ERROR,
                  "Unexpected type of the message",
                  socket_fd_);
}

void Connection::HandleRsaKeyMessage(const RsaPublicKey& rsa_public_key) {
  if (!rsa_public_key_.empty()) {
    SendInfoMessage(Info::UNEXPECTED_MESSAGE_ERROR,
                    "Authentication is already completed. Server is not expecting a message with the RSA key.",
                    socket_fd_);
    return;
  }

  rsa_public_key_ = rsa_public_key.key();
  if (!storage_->contains(rsa_public_key_)) {
    storage_->emplace(rsa_public_key_, std::make_unique<Storage>());
  }

  SendInfoMessage(Info::OK, "Received RSA public key", socket_fd_);
}

void Connection::HandleSessionKeyMessage(const SessionKey& session_key) {
  aes_encryption_key_ = Generate256BitKey();
  auto encrypted_aes_encryption_key =
      EncryptStringWithRsaPublicKey(aes_encryption_key_, rsa_public_key_);
  if (!encrypted_aes_encryption_key.ok()) {
    SendInfoMessage(Info::INTERNAL_SERVER_ERROR,
                    "Server error occurred when trying to encrypt the session key.",
                    socket_fd_);
    return;
  }

  int64_t current_time =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  aes_key_expiration_time_ = current_time + 60 * 60;  // 1 hour from now

  SessionKey session_key_proto;
  session_key_proto.set_encryption_key(*encrypted_aes_encryption_key);
  session_key_proto.set_expiration_time(aes_key_expiration_time_);

  Message message_to_send;
  *message_to_send.mutable_session_key() = std::move(session_key_proto);
  SendUnencryptedMessage(message_to_send, socket_fd_).IgnoreError();
}

void Connection::HandleDataOperationMessage(const DataOperation& data_operation) {
  auto operation_type = data_operation.type();

  if (operation_type == DataOperation::GET) {
    auto content = storage_->at(rsa_public_key_)->GetData(data_operation.key());
    if (!content.has_value()) {
      SendInfoMessage(Info::DATA_NOT_FOUND_ERROR,
                      "No data found by the received key.",
                      socket_fd_);
      return;
    }

    DataOperation data_operation_to_send;
    data_operation_to_send.set_key(data_operation.key());
    data_operation_to_send.set_content(content.value().content);
    data_operation_to_send.set_content_encryption_init_vector(
        content.value().init_vector);

    Message message_to_send;
    *message_to_send.mutable_data_operation() =
        std::move(data_operation_to_send);
    EncryptAndSendMessage(message_to_send,
                          socket_fd_,
                          aes_encryption_key_).IgnoreError();
    return;
  }

  if (operation_type == DataOperation::UPDATE) {
    storage_->at(rsa_public_key_)->PutData(
        data_operation.key(), data_operation.content(),
        data_operation.content_encryption_init_vector());
    SendInfoMessage(Info::OK, "Successfully updated the data", socket_fd_);
    return;
  }

  if (operation_type == DataOperation::DELETE) {
    auto status =
        storage_->at(rsa_public_key_)->RemoveData(data_operation.key());
    if (!status.ok()) {
      SendInfoMessage(Info::DATA_NOT_FOUND_ERROR,
                      "No data found by the received key.",
                      socket_fd_);
    } else {
      SendInfoMessage(Info::OK, "Successfully deleted the data", socket_fd_);
    }
    return;
  }
}

bool Connection::IsClosed() const {
  using namespace std::chrono_literals;
  return is_closed_future_.wait_for(0ms) == std::future_status::ready;
}
