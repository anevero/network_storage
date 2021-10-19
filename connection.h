#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <future>
#include <memory>
#include <string>
#include <thread>

#include "message.pb.h"
#include "storage.h"

class Connection {
 public:
  // Establishes connection and runs an event loop for it in a separate thread.
  // Does not perform any additional operations (like authentication).
  Connection(absl::flat_hash_map<std::string,
                                 std::unique_ptr<Storage>>* storage,
             int socket_fd);

  // Closes connection.
  ~Connection();

  Connection(const Connection& other) = delete;
  Connection& operator=(const Connection& other) = delete;

  bool IsClosed() const;

 private:
  // Waits for the input data and processes it. Returns when the client
  // initiates shutdown.
  void RunEventLoop();

  // Handles the received message. Analyzes its content and current state of
  // the cryptography parameters fields, and runs a corresponding helper.
  void HandleReceivedMessage(const Message& message);

  // Handles a message with the RSA public key. Sets it to the internal field
  // of the class or returns an error, if some key is already set.
  void HandleRsaKeyMessage(const RsaPublicKey& rsa_public_key);

  // Handles a message with the session key (assuming that it's session key
  // request). Generates a session key, encrypts it with the RSA public key and
  // sends it to the caller.
  void HandleSessionKeyMessage(const SessionKey& session_key);

  // Handles a message with the data operation. Performs necessary storage
  // operations and returns OK, an error or some content to the caller.
  void HandleDataOperationMessage(const DataOperation& data_operation);

 private:
  const int socket_fd_;

  // RSA public key -> client's storage
  absl::flat_hash_map<std::string, std::unique_ptr<Storage>>* storage_;

  std::string rsa_public_key_;
  std::string aes_encryption_key_;
  int64_t aes_key_expiration_time_ = 0;

  std::thread thread_;
  std::promise<void> is_closed_;
  std::future<void> is_closed_future_;
};

#endif  // CONNECTION_H_
