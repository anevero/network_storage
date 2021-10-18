#ifndef UTILS_H_
#define UTILS_H_

#include "message.pb.h"

void SendMessage(int socket_fd, const Message& message);

#endif  // UTILS_H_
