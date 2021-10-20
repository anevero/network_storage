#ifndef UTILS_H_
#define UTILS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

#include "message.pb.h"

// Number of times the utilities below will try to send / receive the message
// if some error occurred.
constexpr int kRetriesNumber = 5;

// Converts a message to the binary representation, and writes it to the passed
// socket. Returns an error if the operation is not successful.
absl::Status SendUnencryptedMessage(const Message& message, int socket_fd);

// Converts a message to the binary representation, encrypts it using the
// AES-256-CBC algorithm (with the passed encryption key and a random
// initialization vector) and writes it to the passed socket. Returns an error
// if the operation is not successful.
absl::Status EncryptAndSendMessage(const Message& message, int socket_fd,
                                   const std::string& aes_encryption_key);

// Reads data from the socket, decrypts it if necessary, and returns a parsed
// message. The encryption key variable is not used if the received message
// is not encrypted.
absl::StatusOr<Message> ReceiveAndDecryptMessage(
    int socket_fd, const std::string& aes_encryption_key);

// The function operates with standard input stream, printing the passed
// prompt and parsing a string which is entered by the user. It ensures the
// proper handling of spaces in this string (\n is used as a delimiter).
std::string RequestStringInput(absl::string_view prompt);

#endif  // UTILS_H_
