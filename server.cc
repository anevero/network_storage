#include <iostream>
#include <list>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "absl/container/flat_hash_map.h"

#include "connection.h"
#include "storage.h"

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "Invalid arguments.\n"
              << "Arguments format: ./server [ip] [port]\n"
              << "Example: ./server 127.0.0.1 8701\n";
    return 1;
  }
  const std::string server_ip = argv[1];
  const uint16_t server_port = std::stoi(argv[2]);

  absl::flat_hash_map<std::string, std::unique_ptr<Storage>> storage;

  int socket_fd = socket(AF_INET, SOCK_STREAM, 6);
  if (socket_fd == -1) {
    perror("Error creating socket");
    return 1;
  }

  const sockaddr_in socket_address = {
      .sin_family = AF_INET,
      .sin_port = htons(server_port),
      .sin_addr = {inet_addr(server_ip.c_str())}};

  if (bind(socket_fd, reinterpret_cast<const sockaddr*>(&socket_address),
           sizeof(socket_address)) == -1) {
    perror("Error binding socket");
    if (close(socket_fd) == -1) {
      perror("Error closing socket");
    }
    return 1;
  }

  if (listen(socket_fd, 5) == -1) {
    perror("Error enabling socket to listen");
    if (close(socket_fd) == -1) {
      perror("Error closing socket");
    }
    return 1;
  }

  std::list<Connection> connections;

  while (true) {
    sockaddr_in client_socket_address{};
    socklen_t sock_addr_size = sizeof(sockaddr_in);
    int client_socket_fd = accept(
        socket_fd,
        reinterpret_cast<sockaddr*>(&client_socket_address),
        &sock_addr_size);
    if (client_socket_fd == -1) {
      perror("Error accepting connection from client");
      continue;
    }
    connections.emplace_back(&storage, client_socket_fd);
    connections.remove_if([](const Connection& connection) {
      return connection.IsClosed();
    });
  }

  return 0;
}
