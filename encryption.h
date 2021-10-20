#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <cstdint>
#include <string>

#include "absl/status/statusor.h"

std::string Generate128BitKey();

std::string Generate256BitKey();

absl::StatusOr<std::string> EncryptStringWithAesCbcCipher(
    const std::string& string_to_encrypt,
    const std::string& key_string, const std::string& init_vector_string);

absl::StatusOr<std::string> DecryptStringWithAesCbcCipher(
    const std::string& string_to_decrypt,
    const std::string& key_string, const std::string& init_vector_string);

struct RsaKeysPair {
  std::string public_key;
  std::string private_key;
};

absl::StatusOr<RsaKeysPair> GenerateRsaKeyPair();

absl::StatusOr<std::string> EncryptStringWithRsaPublicKey(
    const std::string& string_to_encrypt, const std::string& key_string);

absl::StatusOr<std::string> DecryptStringWithRsaPrivateKey(
    const std::string& string_to_decrypt, const std::string& key_string);

std::string GetSha256Hash(const std::string& string);

#endif  // ENCRYPTION_H_
