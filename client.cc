#include <cstdint>
#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>
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

void HandleGenerateRsaKeysOperation(std::string* rsa_public_key,
                                    std::string* rsa_private_key) {
  if (!rsa_public_key->empty() && !rsa_private_key->empty()) {
    std::cout << "RSA keys already exist." << std::endl;
    return;
  }

  auto key_pair = GenerateRsaKeyPair();
  *rsa_public_key = std::move(key_pair.public_key);
  *rsa_private_key = std::move(key_pair.private_key);
}

void HandleLoadRsaKeysOperation(std::string* rsa_public_key,
                                std::string* rsa_private_key) {
  if (!rsa_public_key->empty() && !rsa_private_key->empty()) {
    std::cout << "RSA keys already exist." << std::endl;
    return;
  }

  std::cout << "Enter the public key filename: ";
  std::string public_key_filename;
  while (public_key_filename.empty()) {
    std::getline(std::cin, public_key_filename, '\n');
  }

  std::cout << "Enter the private key filename: ";
  std::string private_key_filename;
  while (private_key_filename.empty()) {
    std::getline(std::cin, private_key_filename, '\n');
  }

  std::ifstream public_key_file(public_key_filename);
  std::stringstream public_key_buffer;
  public_key_buffer << public_key_file.rdbuf();
  *rsa_public_key = public_key_buffer.str();

  std::ifstream private_key_file(private_key_filename);
  std::stringstream private_key_buffer;
  private_key_buffer << private_key_file.rdbuf();
  *rsa_private_key = private_key_buffer.str();
}

void HandleSaveRsaKeysOperation(const std::string& rsa_public_key,
                                const std::string& rsa_private_key) {
  std::cout << "Enter the public key filename: ";
  std::string public_key_filename;
  while (public_key_filename.empty()) {
    std::getline(std::cin, public_key_filename, '\n');
  }

  std::cout << "Enter the private key filename: ";
  std::string private_key_filename;
  while (private_key_filename.empty()) {
    std::getline(std::cin, private_key_filename, '\n');
  }

  std::ofstream public_key_file(public_key_filename);
  public_key_file << rsa_public_key;

  std::ofstream private_key_file(private_key_filename);
  private_key_file << rsa_private_key;
}

bool HandleSendRsaPublicKeyOperation(int socket_fd,
                                     const std::string& rsa_public_key) {
  if (rsa_public_key.empty()) {
    std::cout << "Please load or generate key pair firstly." << std::endl;
    return false;
  }

  RsaPublicKey rsa_public_key_proto;
  rsa_public_key_proto.set_key(rsa_public_key);
  Message message;
  *message.mutable_rsa_public_key() = std::move(rsa_public_key_proto);
  SendMessage(socket_fd, message);

  return true;
}

void HandleUpdateSessionKeyOperation(int socket_fd) {
  SessionKey session_key_proto;
  Message message_to_send;
  *message_to_send.mutable_session_key() = std::move(session_key_proto);
  SendMessage(socket_fd, message_to_send);
}

void HandleSetPasswordOperation(std::string* password_hash_key) {
  std::cout << "Enter new password: ";
  std::string password;
  while (password.empty()) {
    std::getline(std::cin, password, '\n');
  }
  *password_hash_key = GetSha256Hash(password);
}

bool HandleGetFileOperation(int socket_fd,
                            const std::string& aes_encryption_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return false;
  }

  std::cout << "Enter the filename: ";
  std::string filename;
  while (filename.empty()) {
    std::getline(std::cin, filename, '\n');
  }
  filename = GetSha256Hash(filename);

  auto message_encryption_init_vector = Generate128BitKey();
  auto encrypted_filename = EncryptStringWithAesCbcCipher(
      filename, aes_encryption_key, message_encryption_init_vector);

  FileOperation file_operation_proto;
  file_operation_proto.set_type(FileOperation::GET);
  file_operation_proto.set_filename(encrypted_filename);
  file_operation_proto.set_message_encryption_init_vector(
      message_encryption_init_vector);

  Message message_to_send;
  *message_to_send.mutable_file_operation() =
      std::move(file_operation_proto);
  SendMessage(socket_fd, message_to_send);

  return true;
}

bool HandleUpdateFileOperation(int socket_fd,
                               const std::string& aes_encryption_key,
                               const std::string& password_hash_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return false;
  }

  std::cout << "Enter the filename: ";
  std::string filename;
  while (filename.empty()) {
    std::getline(std::cin, filename, '\n');
  }
  filename = GetSha256Hash(filename);

  std::cout << "Enter the content: ";
  std::string content;
  while (content.empty()) {
    std::getline(std::cin, content, '\n');
  }

  auto message_encryption_init_vector = Generate128BitKey();
  auto content_encryption_init_vector = Generate128BitKey();

  auto encrypted_filename = EncryptStringWithAesCbcCipher(
      filename, aes_encryption_key, message_encryption_init_vector);
  auto encrypted_content = EncryptStringWithAesCbcCipher(
      content, password_hash_key, content_encryption_init_vector);
  encrypted_content = EncryptStringWithAesCbcCipher(
      encrypted_content, aes_encryption_key, message_encryption_init_vector);

  FileOperation file_operation_proto;
  file_operation_proto.set_type(FileOperation::UPDATE);
  file_operation_proto.set_filename(encrypted_filename);
  file_operation_proto.set_content(encrypted_content);
  file_operation_proto.set_message_encryption_init_vector(
      message_encryption_init_vector);
  file_operation_proto.set_content_encryption_init_vector(
      content_encryption_init_vector);

  Message message_to_send;
  *message_to_send.mutable_file_operation() =
      std::move(file_operation_proto);
  SendMessage(socket_fd, message_to_send);

  return true;
}

bool HandleDeleteFileOperation(int socket_fd,
                               const std::string& aes_encryption_key) {
  if (aes_encryption_key.empty()) {
    std::cout << "Please update yor session key firstly." << std::endl;
    return false;
  }

  std::cout << "Enter the filename: ";
  std::string filename;
  while (filename.empty()) {
    std::getline(std::cin, filename, '\n');
  }
  filename = GetSha256Hash(filename);

  auto message_encryption_init_vector = Generate128BitKey();
  auto encrypted_filename = EncryptStringWithAesCbcCipher(
      filename, aes_encryption_key, message_encryption_init_vector);

  FileOperation file_operation_proto;
  file_operation_proto.set_type(FileOperation::DELETE);
  file_operation_proto.set_filename(encrypted_filename);
  file_operation_proto.set_message_encryption_init_vector(
      message_encryption_init_vector);

  Message message_to_send;
  *message_to_send.mutable_file_operation() =
      std::move(file_operation_proto);
  SendMessage(socket_fd, message_to_send);

  return true;
}

}

constexpr absl::string_view kHelloText = R"(
Choose an operation from the following:
- generate_rsa_keys / load_rsa_keys / save_rsa_keys
- send_rsa_public_key
- update_session_key
- set_password / reset_password
- get_file / update_file / delete_file
- exit)";

constexpr absl::string_view kHelpText = R"(
Arguments format:
./client [server ip] [server port]
Example:
./client 127.0.0.1 8701)";

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cout << "Invalid arguments.\n" << kHelpText << '\n';
    return 1;
  }
  const std::string server_ip = argv[1];
  const uint16_t server_port = std::stoi(argv[2]);

  const int32_t kBufferSize = 4096;
  auto buffer = std::make_unique<char[]>(kBufferSize);

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
  std::string password_hash_key = std::string(32, 't');

  while (true) {
    std::cout << kHelloText << "\n: ";
    std::cout.flush();
    std::string operation;
    std::cin >> operation;

    if (operation == "exit") {
      break;
    }

    if (operation == "generate_rsa_keys") {
      HandleGenerateRsaKeysOperation(&rsa_public_key, &rsa_private_key);
      continue;
    } else if (operation == "load_rsa_keys") {
      HandleLoadRsaKeysOperation(&rsa_public_key, &rsa_private_key);
      continue;
    } else if (operation == "save_rsa_keys") {
      HandleSaveRsaKeysOperation(rsa_public_key, rsa_private_key);
      continue;
    } else if (operation == "send_rsa_public_key") {
      if (!HandleSendRsaPublicKeyOperation(socket_fd, rsa_public_key)) {
        continue;
      }
    } else if (operation == "update_session_key") {
      HandleUpdateSessionKeyOperation(socket_fd);
    } else if (operation == "set_password") {
      HandleSetPasswordOperation(&password_hash_key);
      continue;
    } else if (operation == "reset_password") {
      password_hash_key = std::string(32, 't');
      continue;
    } else if (operation == "get_file") {
      if (!HandleGetFileOperation(socket_fd, aes_encryption_key)) {
        continue;
      }
    } else if (operation == "update_file") {
      if (!HandleUpdateFileOperation(
          socket_fd, aes_encryption_key, password_hash_key)) {
        continue;
      }
    } else if (operation == "delete_file") {
      if (!HandleDeleteFileOperation(socket_fd, aes_encryption_key)) {
        continue;
      }
    } else {
      std::cout << "Unsupported operation." << std::endl;
      continue;
    }

    std::memset(buffer.get(), 0, kBufferSize);
    ssize_t buffer_actual_size = read(socket_fd, buffer.get(), kBufferSize);

    if (buffer_actual_size == -1) {
      perror("Error reading received message");
      continue;
    } else if (buffer_actual_size == 0) {
      std::cout << "Server has disconnected" << std::endl;
      break;
    }

    Message received_message;
    if (!received_message.ParseFromString(
        std::string(buffer.get(), buffer.get() + buffer_actual_size))) {
      std::cout << "Received message is corrupted." << std::endl;
      continue;
    }

    if (received_message.has_session_key()) {
      std::cout << "Received a message with the session key." << std::endl;
      auto& encrypted_aes_encryption_key =
          received_message.session_key().encryption_key();
      aes_encryption_key = DecryptStringWithRsaPrivateKey(
          encrypted_aes_encryption_key, rsa_private_key);
      continue;
    }

    if (received_message.has_error_info()) {
      std::cout << "Received a message with error info of type "
                << ErrorInfo::Type_Name(received_message.error_info().type())
                << " and description '"
                << received_message.error_info().description() << "'."
                << std::endl;
      continue;
    }

    if (received_message.has_ok_info()) {
      std::cout << "Received a message with OK status and description '"
                << received_message.ok_info().description() << "'."
                << std::endl;
      continue;
    }

    if (received_message.has_file_operation()) {
      std::cout << "Received a message with file content:" << std::endl;
      auto decrypted_content = DecryptStringWithAesCbcCipher(
          received_message.file_operation().content(),
          aes_encryption_key,
          received_message.file_operation().message_encryption_init_vector());

      try {
        decrypted_content = DecryptStringWithAesCbcCipher(
            decrypted_content,
            password_hash_key,
            received_message.file_operation().content_encryption_init_vector());
        std::cout << decrypted_content << std::endl;
      } catch (...) {
        std::cout << "Decryption error occurred. "
                  << "Probably, the received file was encrypted with a different password. "
                  << "Please set the necessary password before requesting this file."
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
