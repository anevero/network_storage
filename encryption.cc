#include "encryption.h"

#include <limits>
#include <memory>
#include <stdexcept>

#include "absl/random/random.h"

#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"

namespace {

CryptoPP::AutoSeededRandomPool cryptopp_random_generator;

absl::BitGen absl_random_generator;

}  // namespace

std::string Generate128BitKey() {
  auto key = std::make_unique<uint64_t[]>(2);
  for (int i = 0; i < 2; ++i) {
    key[i] = absl::Uniform<uint64_t>(
        absl::IntervalClosed, absl_random_generator,
        0, std::numeric_limits<uint64_t>::max());
  }
  return {reinterpret_cast<char*>(key.get()), 16};
}

std::string Generate256BitKey() {
  auto key = std::make_unique<uint64_t[]>(4);
  for (int i = 0; i < 4; ++i) {
    key[i] = absl::Uniform<uint64_t>(
        absl::IntervalClosed, absl_random_generator,
        0, std::numeric_limits<uint64_t>::max());
  }
  return {reinterpret_cast<char*>(key.get()), 32};
}

absl::StatusOr<std::string> EncryptStringWithAesCbcCipher(
    const std::string& string_to_encrypt,
    const std::string& key_string, const std::string& init_vector_string) {
  CryptoPP::SecByteBlock key(
      reinterpret_cast<const unsigned char*>(
          key_string.data()), key_string.size());
  CryptoPP::SecByteBlock init_vector(
      reinterpret_cast<const unsigned char*>(
          init_vector_string.data()), init_vector_string.size());

  CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
  std::string result_string;

  try {
    encryptor.SetKeyWithIV(key, key.size(), init_vector);
    CryptoPP::StringSource s(
        string_to_encrypt, true, new CryptoPP::StreamTransformationFilter(
            encryptor, new CryptoPP::StringSink(result_string)));
  } catch (std::exception& exception) {
    return absl::InternalError(exception.what());
  }

  return result_string;
}

absl::StatusOr<std::string> DecryptStringWithAesCbcCipher(
    const std::string& string_to_decrypt,
    const std::string& key_string, const std::string& init_vector_string) {
  CryptoPP::SecByteBlock key(
      reinterpret_cast<const unsigned char*>(
          key_string.data()), key_string.size());
  CryptoPP::SecByteBlock init_vector(
      reinterpret_cast<const unsigned char*>(
          init_vector_string.data()), init_vector_string.size());

  CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
  std::string result_string;

  try {
    decryptor.SetKeyWithIV(key, key.size(), init_vector);
    CryptoPP::StringSource s(
        string_to_decrypt, true, new CryptoPP::StreamTransformationFilter(
            decryptor, new CryptoPP::StringSink(result_string)));
  } catch (std::exception& exception) {
    return absl::InternalError(exception.what());
  }

  return result_string;
}

absl::StatusOr<RsaKeysPair> GenerateRsaKeyPair() {
  CryptoPP::InvertibleRSAFunction parameters;
  RsaKeysPair result;

  try {
    parameters.GenerateRandomWithKeySize(cryptopp_random_generator, 4096);
    CryptoPP::RSA::PrivateKey private_key(parameters);
    CryptoPP::RSA::PublicKey public_key(parameters);

    CryptoPP::StringSink private_ss(result.private_key);
    CryptoPP::StringSink public_ss(result.public_key);
    private_key.DEREncode(private_ss);
    public_key.DEREncode(public_ss);
  } catch (std::exception& exception) {
    return absl::InternalError(exception.what());
  }

  return result;
}

absl::StatusOr<std::string> EncryptStringWithRsaPublicKey(
    const std::string& string_to_encrypt, const std::string& rsa_public_key) {
  CryptoPP::RSA::PublicKey key;
  std::string result_string;

  try {
    CryptoPP::StringSource public_ss(rsa_public_key, true);
    key.BERDecode(public_ss);

    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);
    CryptoPP::StringSource s(
        string_to_encrypt, true, new CryptoPP::PK_EncryptorFilter(
            cryptopp_random_generator, encryptor,
            new CryptoPP::StringSink(result_string)));
  } catch (std::exception& exception) {
    return absl::InternalError(exception.what());
  }

  return result_string;
}

absl::StatusOr<std::string> DecryptStringWithRsaPrivateKey(
    const std::string& string_to_decrypt, const std::string& rsa_private_key) {
  CryptoPP::RSA::PrivateKey key;
  std::string result_string;

  try {
    CryptoPP::StringSource private_ss(rsa_private_key, true);
    key.BERDecode(private_ss);

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
    CryptoPP::StringSource s(
        string_to_decrypt, true, new CryptoPP::PK_DecryptorFilter(
            cryptopp_random_generator, decryptor,
            new CryptoPP::StringSink(result_string)));
  } catch (std::exception& exception) {
    return absl::InternalError(exception.what());
  }

  return result_string;
}

std::string GetSha256Hash(const std::string& string) {
  std::string result;
  CryptoPP::SHA256 hasher;
  CryptoPP::StringSource s(string, true, new CryptoPP::HashFilter(
      hasher, new CryptoPP::StringSink(result)));
  return result;
}
