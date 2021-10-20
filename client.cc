#include <cstdint>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "absl/strings/string_view.h"

#include "encryption.h"
#include "message.pb.h"
#include "utils.h"

namespace {

// All the handlers for the client-requested operations are defined in this
// unnamed namespace. All the handlers return a WaitForServerResponse value
// indicating if we need to wait for some response from the server or if we can
// continue to the next operations from the user side.

enum class WaitForServerResponse {
  kEnabled,
  kDisabled
};

WaitForServerResponse HandleGenerateRsaKeysOperation(
    std::string* rsa_public_key, std::string* rsa_private_key) {
  if (!rsa_public_key->empty() && !rsa_private_key->empty()) {
    std::cout << "RSA keys already exist." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  auto key_pair = GenerateRsaKeyPair();
  *rsa_public_key = std::move(key_pair.public_key);
  *rsa_private_key = std::move(key_pair.private_key);

  return WaitForServerResponse::kDisabled;
}

WaitForServerResponse HandleLoadRsaKeysOperation(
    std::string* rsa_public_key, std::string* rsa_private_key) {
  if (!rsa_public_key->empty() && !rsa_private_key->empty()) {
    std::cout << "RSA keys already exist." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  auto public_key_filename = RequestStringInput(
      "Enter the public key filename");
  auto private_key_filename = RequestStringInput(
      "Enter the private key filename");

  std::ifstream public_key_file(public_key_filename);
  std::stringstream public_key_buffer;
  public_key_buffer << public_key_file.rdbuf();
  *rsa_public_key = public_key_buffer.str();

  std::ifstream private_key_file(private_key_filename);
  std::stringstream private_key_buffer;
  private_key_buffer << private_key_file.rdbuf();
  *rsa_private_key = private_key_buffer.str();

  return WaitForServerResponse::kDisabled;
}

WaitForServerResponse HandleSaveRsaKeysOperation(
    const std::string& rsa_public_key, const std::string& rsa_private_key) {
  auto public_key_filename = RequestStringInput(
      "Enter the public key filename");
  auto private_key_filename = RequestStringInput(
      "Enter the private key filename");

  std::ofstream public_key_file(public_key_filename);
  public_key_file << rsa_public_key;

  std::ofstream private_key_file(private_key_filename);
  private_key_file << rsa_private_key;

  return WaitForServerResponse::kDisabled;
}

WaitForServerResponse HandleSendRsaPublicKeyOperation(
    int socket_fd, const std::string& rsa_public_key) {
  if (rsa_public_key.empty()) {
    std::cout << "Please load or generate key pair firstly." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  RsaPublicKey rsa_public_key_proto;
  rsa_public_key_proto.set_key(rsa_public_key);
  Message message_to_send;
  *message_to_send.mutable_rsa_public_key() = std::move(rsa_public_key_proto);

  auto status = SendUnencryptedMessage(message_to_send, socket_fd);
  if (!status.ok()) {
    std::cout << status << std::endl;
    return WaitForServerResponse::kDisabled;
  }
  return WaitForServerResponse::kEnabled;
}

WaitForServerResponse HandleUpdateSessionKeyOperation(int socket_fd) {
  SessionKey session_key_proto;
  Message message_to_send;
  *message_to_send.mutable_session_key() = std::move(session_key_proto);

  auto status = SendUnencryptedMessage(message_to_send, socket_fd);
  if (!status.ok()) {
    std::cout << status << std::endl;
    return WaitForServerResponse::kDisabled;
  }
  return WaitForServerResponse::kEnabled;
}

WaitForServerResponse HandleSetPasswordOperation(
    std::string* password_hash_key) {
  auto password = RequestStringInput("Enter new password");
  *password_hash_key = GetSha256Hash(password);
  return WaitForServerResponse::kDisabled;
}

WaitForServerResponse HandleResetPasswordOperation(
    std::string* password_hash_key) {
  *password_hash_key = "dshflshfg7598vn7435342nqwe57vnw5";
  return WaitForServerResponse::kDisabled;
}

WaitForServerResponse HandleGetDataOperation(
    int socket_fd, const std::string& aes_encryption_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  auto key = GetSha256Hash(RequestStringInput("Enter the key"));
  DataOperation data_operation_proto;
  data_operation_proto.set_type(DataOperation::GET);
  data_operation_proto.set_key(key);

  Message message_to_send;
  *message_to_send.mutable_data_operation() = std::move(data_operation_proto);

  auto status = SendUnencryptedMessage(message_to_send, socket_fd);
  if (!status.ok()) {
    std::cout << status << std::endl;
    return WaitForServerResponse::kDisabled;
  }
  return WaitForServerResponse::kEnabled;
}

WaitForServerResponse HandleUpdateDataOperation(
    int socket_fd,
    const std::string& aes_encryption_key,
    const std::string& password_hash_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  auto key = GetSha256Hash(RequestStringInput("Enter the key"));
  auto content = RequestStringInput("Enter the content (line)");

  auto content_encryption_init_vector = Generate128BitKey();
  auto encrypted_content = EncryptStringWithAesCbcCipher(
      content, password_hash_key, content_encryption_init_vector);

  DataOperation data_operation_proto;
  data_operation_proto.set_type(DataOperation::UPDATE);
  data_operation_proto.set_key(key);
  data_operation_proto.set_content(encrypted_content);
  data_operation_proto.set_content_encryption_init_vector(
      content_encryption_init_vector);

  Message message_to_send;
  *message_to_send.mutable_data_operation() = std::move(data_operation_proto);

  auto status = SendUnencryptedMessage(message_to_send, socket_fd);
  if (!status.ok()) {
    std::cout << status << std::endl;
    return WaitForServerResponse::kDisabled;
  }
  return WaitForServerResponse::kEnabled;
}

WaitForServerResponse HandleDeleteDataOperation(
    int socket_fd, const std::string& aes_encryption_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return WaitForServerResponse::kDisabled;
  }

  auto key = GetSha256Hash(RequestStringInput("Enter the key"));
  DataOperation data_operation_proto;
  data_operation_proto.set_type(DataOperation::DELETE);
  data_operation_proto.set_key(key);

  Message message_to_send;
  *message_to_send.mutable_data_operation() = std::move(data_operation_proto);

  auto status = SendUnencryptedMessage(message_to_send, socket_fd);
  if (!status.ok()) {
    std::cout << status << std::endl;
    return WaitForServerResponse::kDisabled;
  }
  return WaitForServerResponse::kEnabled;
}

}  // namespace

constexpr absl::string_view kProgramFeaturesPrompt = R"(
Choose an operation from the following:
- generate_rsa_keys / load_rsa_keys / save_rsa_keys
- send_rsa_public_key
- update_session_key
- set_password / reset_password
- get_data / update_data / delete_data
- exit)";

constexpr absl::string_view kProgramRunningHelpText = R"(
Arguments format:
./client [server ip] [server port]
Example:
./client 127.0.0.1 8701)";

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cout << "Invalid arguments.\n" << kProgramRunningHelpText << '\n';
    return 1;
  }
  const std::string server_ip = argv[1];
  const uint16_t server_port = std::stoi(argv[2]);

  int socket_fd = socket(AF_INET, SOCK_STREAM, 6);
  if (socket_fd == -1) {
    perror("Error creating socket");
    return 1;
  }

  const sockaddr_in server_address = {
      .sin_family = AF_INET,
      .sin_port = htons(server_port),
      .sin_addr = {inet_addr(server_ip.c_str())}};

  if (connect(socket_fd,
              reinterpret_cast<const sockaddr*>(&server_address),
              sizeof(sockaddr_in)) == -1) {
    perror("Error establishing connection");
    return 1;
  }

  std::string rsa_public_key;
  std::string rsa_private_key;
  std::string aes_encryption_key;
  std::string password_hash_key;
  HandleResetPasswordOperation(&password_hash_key);

  while (true) {
    auto operation = RequestStringInput(kProgramFeaturesPrompt);
    WaitForServerResponse status;

    if (operation == "exit") {
      break;
    } else if (operation == "generate_rsa_keys") {
      status = HandleGenerateRsaKeysOperation(
          &rsa_public_key, &rsa_private_key);
    } else if (operation == "load_rsa_keys") {
      status = HandleLoadRsaKeysOperation(&rsa_public_key, &rsa_private_key);
    } else if (operation == "save_rsa_keys") {
      status = HandleSaveRsaKeysOperation(rsa_public_key, rsa_private_key);
    } else if (operation == "send_rsa_public_key") {
      status = HandleSendRsaPublicKeyOperation(socket_fd, rsa_public_key);
    } else if (operation == "update_session_key") {
      status = HandleUpdateSessionKeyOperation(socket_fd);
    } else if (operation == "set_password") {
      status = HandleSetPasswordOperation(&password_hash_key);
    } else if (operation == "reset_password") {
      status = HandleResetPasswordOperation(&password_hash_key);
    } else if (operation == "get_data") {
      status = HandleGetDataOperation(socket_fd, aes_encryption_key);
    } else if (operation == "update_data") {
      status = HandleUpdateDataOperation(
          socket_fd, aes_encryption_key, password_hash_key);
    } else if (operation == "delete_data") {
      status = HandleDeleteDataOperation(socket_fd, aes_encryption_key);
    } else {
      std::cout << "Unsupported operation." << std::endl;
      continue;
    }

    if (status == WaitForServerResponse::kDisabled) {
      continue;
    }

    auto received_message =
        ReceiveAndDecryptMessage(socket_fd, aes_encryption_key);
    if (!received_message.ok()) {
      std::cout << received_message.status();
      if (absl::IsCancelled(received_message.status())) {
        break;
      }
      continue;
    }

    if (received_message->has_session_key()) {
      std::cout << "Received a message with the session key." << std::endl;
      auto& encrypted_aes_encryption_key =
          received_message->session_key().encryption_key();
      aes_encryption_key = DecryptStringWithRsaPrivateKey(
          encrypted_aes_encryption_key, rsa_private_key);
      continue;
    }

    if (received_message->has_error_info()) {
      std::cout << "Received a message with error info of type "
                << ErrorInfo::Type_Name(received_message->error_info().type())
                << " and description '"
                << received_message->error_info().description() << "'."
                << std::endl;
      continue;
    }

    if (received_message->has_ok_info()) {
      std::cout << "Received a message with OK status and description '"
                << received_message->ok_info().description() << "'."
                << std::endl;
      continue;
    }

    if (received_message->has_data_operation()) {
      std::cout << "Received a message with the content" << std::endl;
      try {
        auto decrypted_content = DecryptStringWithAesCbcCipher(
            received_message->data_operation().content(), password_hash_key,
            received_message->data_operation().content_encryption_init_vector());
        std::cout << decrypted_content << std::endl;
      } catch (...) {
        std::cout << "Decryption error occurred. "
                  << "Probably, the received data was encrypted with a different password. "
                  << "Please set the necessary password before requesting this data."
                  << std::endl;
      }
      continue;
    }
  }

  std::cout << "Shutting connection down" << std::endl;
  if (shutdown(socket_fd, SHUT_RDWR) == -1) {
    perror("Error shutting socket down");
    if (close(socket_fd) == -1) {
      perror("Error closing socket");
    }
    return 1;
  }
  if (close(socket_fd) == -1) {
    perror("Error closing socket");
    return 1;
  }

  return 0;
}
