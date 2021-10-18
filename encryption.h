#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <cstdint>
#include <string>

std::string Generate128BitKey();

std::string Generate256BitKey();

std::string EncryptStringWithAesCbcCipher(
    const std::string& string_to_encrypt,
    const std::string& key_string, const std::string& init_vector_string);

std::string DecryptStringWithAesCbcCipher(
    const std::string& string_to_decrypt,
    const std::string& key_string, const std::string& init_vector_string);

struct RsaKeysPair {
  std::string public_key;
  std::string private_key;
};

RsaKeysPair GenerateRsaKeyPair();

std::string EncryptStringWithRsaPublicKey(
    const std::string& string_to_encrypt, const std::string& key_string);

std::string DecryptStringWithRsaPrivateKey(
    const std::string& string_to_decrypt, const std::string& key_string);

std::string GetSha256Hash(const std::string& string);

#endif  // ENCRYPTION_H_
