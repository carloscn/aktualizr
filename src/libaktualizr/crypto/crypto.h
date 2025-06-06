#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <sodium.h>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <string>
#include <utility>

#include "libaktualizr/types.h"
#include "utilities/utils.h"

// Redefine BIO_new_mem_buf to avoid type issues
#undef BIO_new_mem_buf
BIO *BIO_new_mem_buf(const void *, int);

class MultiPartHasher {
 public:
  using Ptr = std::shared_ptr<MultiPartHasher>;
  static Ptr create(Hash::Type hash_type);

  virtual void update(const unsigned char *part, uint64_t size) = 0;
  virtual void reset() = 0;
  virtual std::string getHexDigest() = 0;
  virtual Hash getHash() = 0;
  virtual ~MultiPartHasher() = default;
};

class MultiPartSHA512Hasher : public MultiPartHasher {
 public:
  MultiPartSHA512Hasher() { crypto_hash_sha512_init(&state_); }
  ~MultiPartSHA512Hasher() override = default;
  void update(const unsigned char *part, uint64_t size) override { crypto_hash_sha512_update(&state_, part, size); }
  void reset() override { crypto_hash_sha512_init(&state_); }
  std::string getHexDigest() override {
    std::array<unsigned char, crypto_hash_sha512_BYTES> sha512_hash{};
    crypto_hash_sha512_final(&state_, sha512_hash.data());
    return boost::algorithm::hex(std::string(reinterpret_cast<char *>(sha512_hash.data()), crypto_hash_sha512_BYTES));
  }
  Hash getHash() override { return Hash(Hash::Type::kSha512, getHexDigest()); }

 private:
  crypto_hash_sha512_state state_{};
};

class MultiPartSHA256Hasher : public MultiPartHasher {
 public:
  MultiPartSHA256Hasher() { crypto_hash_sha256_init(&state_); }
  ~MultiPartSHA256Hasher() override = default;
  void update(const unsigned char *part, uint64_t size) override { crypto_hash_sha256_update(&state_, part, size); }
  void reset() override { crypto_hash_sha256_init(&state_); }
  std::string getHexDigest() override {
    std::array<unsigned char, crypto_hash_sha256_BYTES> sha256_hash{};
    crypto_hash_sha256_final(&state_, sha256_hash.data());
    return boost::algorithm::hex(std::string(reinterpret_cast<char *>(sha256_hash.data()), crypto_hash_sha256_BYTES));
  }
  Hash getHash() override { return Hash(Hash::Type::kSha256, getHexDigest()); }

 private:
  crypto_hash_sha256_state state_{};
};

class Crypto {
 public:
  static std::string sha256digest(const std::string &text);
  static std::string sha512digest(const std::string &text);
  static std::string RSAPSSSign(const std::string &private_key, const std::string &message);
  // Compatibility overload for ENGINE* (ignored)
  static std::string RSAPSSSign(void *engine, const std::string &private_key, const std::string &message) {
    (void)engine; // Suppress unused parameter
    return RSAPSSSign(private_key, message);
  }
  static std::string Sign(KeyType key_type, const std::string &private_key, const std::string &message);
  // Compatibility overload for ENGINE* (ignored)
  static std::string Sign(KeyType key_type, void *engine, const std::string &private_key, const std::string &message) {
    (void)engine; // Suppress unused parameter
    return Sign(key_type, private_key, message);
  }
  static std::string ED25519Sign(const std::string &private_key, const std::string &message);
  static bool parseP12(BIO *p12_bio, const std::string &password, std::string *out_pkey, std::string *out_cert,
                       std::string *out_ca);
  static std::string extractSubjectCN(const std::string &cert);
  static StructGuard<EVP_PKEY> generateRSAKeyPairEVP(KeyType key_type);
  static StructGuard<EVP_PKEY> generateRSAKeyPairEVP(int64_t bits);
  static bool generateRSAKeyPair(KeyType key_type, std::string *public_key, std::string *private_key);
  static bool generateEDKeyPair(std::string *public_key, std::string *private_key);
  static bool generateKeyPair(KeyType key_type, std::string *public_key, std::string *private_key);

  static bool RSAPSSVerify(const std::string &public_key, const std::string &signature, const std::string &message);
  static bool ED25519Verify(const std::string &public_key, const std::string &signature, const std::string &message);

  static bool IsRsaKeyType(KeyType type);
  static KeyType IdentifyRSAKeyType(const std::string &public_key_pem);

  static StructGuard<X509> generateCert(int64_t rsa_bits, int days, const std::string &country, const std::string &state,
                                        const std::string &org, const std::string &cn, bool self_sign = false);
  static void signCert(const std::string &cacert_path, const std::string &capkey_path, X509 *certificate);
  static void serializeCert(std::string *pkey, std::string *cert, X509 *certificate);
};

#endif // CRYPTO_H_
