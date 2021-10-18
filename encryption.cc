#include "encryption.h"

#include <limits>
#include <memory>

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

std::string EncryptStringWithAesCbcCipher(
    const std::string& string_to_encrypt,
    const std::string& key_string, const std::string& init_vector_string) {
  CryptoPP::SecByteBlock key(
      reinterpret_cast<const unsigned char*>(
          key_string.data()), key_string.size());
  CryptoPP::SecByteBlock init_vector(
      reinterpret_cast<const unsigned char*>(
          init_vector_string.data()), init_vector_string.size());

  CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
  encryptor.SetKeyWithIV(key, key.size(), init_vector);
  std::string result_string;

  CryptoPP::StringSource s(
      string_to_encrypt, true, new CryptoPP::StreamTransformationFilter(
          encryptor, new CryptoPP::StringSink(result_string)));

  return result_string;
}

std::string DecryptStringWithAesCbcCipher(
    const std::string& string_to_decrypt,
    const std::string& key_string, const std::string& init_vector_string) {
  CryptoPP::SecByteBlock key(
      reinterpret_cast<const unsigned char*>(
          key_string.data()), key_string.size());
  CryptoPP::SecByteBlock init_vector(
      reinterpret_cast<const unsigned char*>(
          init_vector_string.data()), init_vector_string.size());

  CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
  decryptor.SetKeyWithIV(key, key.size(), init_vector);
  std::string result_string;

  CryptoPP::StringSource s(
      string_to_decrypt, true, new CryptoPP::StreamTransformationFilter(
          decryptor, new CryptoPP::StringSink(result_string)));

  return result_string;
}

RsaKeysPair GenerateRsaKeyPair() {
  CryptoPP::InvertibleRSAFunction parameters;
  parameters.GenerateRandomWithKeySize(cryptopp_random_generator, 4096);

  CryptoPP::RSA::PrivateKey private_key(parameters);
  CryptoPP::RSA::PublicKey public_key(parameters);

  RsaKeysPair result;

  CryptoPP::StringSink private_ss(result.private_key);
  CryptoPP::StringSink public_ss(result.public_key);
  private_key.DEREncode(private_ss);
  public_key.DEREncode(public_ss);

  return result;
}

std::string EncryptStringWithRsaPublicKey(const std::string& string_to_encrypt,
                                          const std::string& rsa_public_key) {
  CryptoPP::RSA::PublicKey key;
  CryptoPP::StringSource public_ss(rsa_public_key, true);
  key.BERDecode(public_ss);

  CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);
  std::string result_string;

  CryptoPP::StringSource s(
      string_to_encrypt, true, new CryptoPP::PK_EncryptorFilter(
          cryptopp_random_generator, encryptor,
          new CryptoPP::StringSink(result_string)));

  return result_string;
}

std::string DecryptStringWithRsaPrivateKey(const std::string& string_to_decrypt,
                                           const std::string& rsa_private_key) {
  CryptoPP::RSA::PrivateKey key;
  CryptoPP::StringSource private_ss(rsa_private_key, true);
  key.BERDecode(private_ss);

  CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
  std::string result_string;

  CryptoPP::StringSource s(
      string_to_decrypt, true, new CryptoPP::PK_DecryptorFilter(
          cryptopp_random_generator, decryptor,
          new CryptoPP::StringSink(result_string)));

  return result_string;
}

std::string GetSha256Hash(const std::string& string) {
  std::string result;
  CryptoPP::SHA256 hasher;
  CryptoPP::StringSource s(string, true, new CryptoPP::HashFilter(
      hasher, new CryptoPP::StringSink(result)));
  return result;
}
