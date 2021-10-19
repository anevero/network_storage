#ifndef UTILS_H_
#define UTILS_H_

#include "absl/strings/string_view.h"

#include "message.pb.h"

// The function writes the content of the message to the passed socket and
// logs an error, if the operation is not successful.
void SendMessage(int socket_fd, const Message& message);

// The function operates with standard input stream, printing the passed
// prompt and parsing a string which is entered by the user. It ensures the
// proper handling of spaces in this string (\n is used as a delimiter).
std::string RequestStringInput(absl::string_view prompt);

#endif  // UTILS_H_
