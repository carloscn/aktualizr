#include "crypto.h"

#include <array>
#include <random>

#include <sodium.h>
#include <boost/algorithm/hex.hpp>
#include <boost/scoped_array.hpp>

#include "libaktualizr/types.h"
#include "logging/logging.h"
#include "utilities/utils.h"

PublicKey::PublicKey(const boost::filesystem::path &path) : value_(Utils::readFile(path)) {
  type_ = Crypto::IdentifyRSAKeyType(value_);
}

PublicKey::PublicKey(const Json::Value &uptane_json) {
  std::string keytype;
  std::string keyvalue;

  try {
    if (!uptane_json["keytype"].isString()) {
      type_ = KeyType::kUnknown;
      return;
    }
    if (!uptane_json["keyval"].isObject()) {
      type_ = KeyType::kUnknown;
      return;
    }
    if (!uptane_json["keyval"]["public"].isString()) {
      type_ = KeyType::kUnknown;
      return;
    }

    keytype = uptane_json["keytype"].asString();
    keyvalue = uptane_json["keyval"]["public"].asString();
  } catch (const std::exception &ex) {
    LOG_ERROR << "Failed to initialize public key: " << ex.what();
    type_ = KeyType::kUnknown;
    return;
  }

  std::transform(keytype.begin(), keytype.end(), keytype.begin(), ::tolower);

  KeyType type;
  if (keytype == "ed25519") {
    type = KeyType::kED25519;
  } else if (keytype == "rsa") {
    type = Crypto::IdentifyRSAKeyType(keyvalue);
    if (type == KeyType::kUnknown) {
      LOG_WARNING << "Couldn't identify length of RSA key";
    }
  } else {
    type = KeyType::kUnknown;
  }
  type_ = type;
  value_ = keyvalue;
}

PublicKey::PublicKey(const std::string &value, KeyType type) : value_(value), type_(type) {
  if (Crypto::IsRsaKeyType(type)) {
    if (type != Crypto::IdentifyRSAKeyType(value)) {
      throw std::logic_error("RSA key length is incorrect");
    }
  }
}

bool PublicKey::VerifySignature(const std::string &signature, const std::string &message) const {
  switch (type_) {
    case KeyType::kED25519:
      return Crypto::ED25519Verify(boost::algorithm::unhex(value_), Utils::fromBase64(signature), message);
    case KeyType::kRSA2048:
    case KeyType::kRSA3072:
    case KeyType::kRSA4096:
      return Crypto::RSAPSSVerify(value_, Utils::fromBase64(signature), message);
    default:
      return false;
  }
}

bool PublicKey::operator==(const PublicKey &rhs) const { return value_ == rhs.value_ && type_ == rhs.type_; }

Json::Value PublicKey::ToUptane() const {
  Json::Value res;
  switch (type_) {
    case KeyType::kRSA2048:
    case KeyType::kRSA3072:
    case KeyType::kRSA4096:
      res["keytype"] = "RSA";
      break;
    case KeyType::kED25519:
      res["keytype"] = "ED25519";
      break;
    case KeyType::kUnknown:
      res["keytype"] = "unknown";
      break;
    default:
      throw std::range_error("Unknown key type in PublicKey::ToUptane");
  }
  res["keyval"]["public"] = value_;
  return res;
}

std::string PublicKey::KeyId() const {
  std::string key_content = value_;
  boost::algorithm::trim_right_if(key_content, boost::algorithm::is_any_of("\n"));
  std::string keyid = boost::algorithm::hex(Crypto::sha256digest(Utils::jsonToCanonicalStr(Json::Value(key_content))));
  std::transform(keyid.begin(), keyid.end(), keyid.begin(), ::tolower);
  return keyid;
}

std::string Crypto::sha256digest(const std::string &text) {
  std::array<unsigned char, crypto_hash_sha256_BYTES> sha256_hash{};
  crypto_hash_sha256(sha256_hash.data(), reinterpret_cast<const unsigned char *>(text.c_str()), text.size());
  return std::string(reinterpret_cast<char *>(sha256_hash.data()), crypto_hash_sha256_BYTES);
}

std::string Crypto::sha512digest(const std::string &text) {
  std::array<unsigned char, crypto_hash_sha512_BYTES> sha512_hash{};
  crypto_hash_sha512(sha512_hash.data(), reinterpret_cast<const unsigned char *>(text.c_str()), text.size());
  return std::string(reinterpret_cast<char *>(sha512_hash.data()), crypto_hash_sha512_BYTES);
}

std::string Crypto::RSAPSSSign(const std::string &private_key, const std::string &message) {
  StructGuard<BIO> bio(BIO_new_mem_buf(const_cast<char *>(private_key.c_str()), static_cast<int>(private_key.size())),
                       [](BIO *b) { BIO_free(b); });
  StructGuard<EVP_PKEY> key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (key == nullptr) {
    LOG_ERROR << "PEM_read_bio_PrivateKey failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  StructGuard<EVP_MD_CTX> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    LOG_ERROR << "EVP_MD_CTX_new failed";
    return std::string();
  }

  if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    LOG_ERROR << "EVP_DigestSignInit failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  EVP_PKEY_CTX *pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx.get());
  if (pkey_ctx == nullptr ||
      EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
    LOG_ERROR << "EVP_PKEY_CTX setup failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  std::string digest = Crypto::sha256digest(message);
  if (EVP_DigestSignUpdate(ctx.get(), digest.c_str(), digest.size()) != 1) {
    LOG_ERROR << "EVP_DigestSignUpdate failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  size_t sig_len;
  if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1) {
    LOG_ERROR << "EVP_DigestSignFinal (size) failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  std::vector<unsigned char> signature(sig_len);
  if (EVP_DigestSignFinal(ctx.get(), signature.data(), &sig_len) != 1) {
    LOG_ERROR << "EVP_DigestSignFinal failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return std::string();
  }

  return std::string(reinterpret_cast<char *>(signature.data()), sig_len);
}

std::string Crypto::Sign(KeyType key_type, const std::string &private_key, const std::string &message) {
  if (key_type == KeyType::kED25519) {
    return Crypto::ED25519Sign(boost::algorithm::unhex(private_key), message);
  }
  return Crypto::RSAPSSSign(private_key, message);
}

std::string Crypto::ED25519Sign(const std::string &private_key, const std::string &message) {
  std::array<unsigned char, crypto_sign_BYTES> sig{};
  crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char *>(message.c_str()), message.size(),
                       reinterpret_cast<const unsigned char *>(private_key.c_str()));
  return std::string(reinterpret_cast<char *>(sig.data()), crypto_sign_BYTES);
}

bool Crypto::RSAPSSVerify(const std::string &public_key, const std::string &signature, const std::string &message) {
  StructGuard<BIO> bio(BIO_new_mem_buf(const_cast<char *>(public_key.c_str()), static_cast<int>(public_key.size())),
                       [](BIO *b) { BIO_free(b); });
  StructGuard<EVP_PKEY> key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (key == nullptr) {
    LOG_ERROR << "PEM_read_bio_PUBKEY failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  StructGuard<EVP_MD_CTX> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    LOG_ERROR << "EVP_MD_CTX_new failed";
    return false;
  }

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    LOG_ERROR << "EVP_DigestVerifyInit failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  EVP_PKEY_CTX *pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx.get());
  if (pkey_ctx == nullptr ||
      EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -2) != 1 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
    LOG_ERROR << "EVP_PKEY_CTX setup failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  std::string digest = Crypto::sha256digest(message);
  if (EVP_DigestVerifyUpdate(ctx.get(), digest.c_str(), digest.size()) != 1) {
    LOG_ERROR << "EVP_DigestVerifyUpdate failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  return EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<const unsigned char *>(signature.c_str()), signature.size()) == 1;
}

bool Crypto::ED25519Verify(const std::string &public_key, const std::string &signature, const std::string &message) {
  if (public_key.size() < crypto_sign_PUBLICKEYBYTES || signature.size() < crypto_sign_BYTES) {
    return false;
  }
  return crypto_sign_verify_detached(reinterpret_cast<const unsigned char *>(signature.c_str()),
                                    reinterpret_cast<const unsigned char *>(message.c_str()), message.size(),
                                    reinterpret_cast<const unsigned char *>(public_key.c_str())) == 0;
}

bool Crypto::parseP12(BIO *p12_bio, const std::string &password, std::string *out_pkey, std::string *out_cert,
                      std::string *out_ca) {
  StructGuard<PKCS12> p12(d2i_PKCS12_bio(p12_bio, nullptr), PKCS12_free);
  if (p12 == nullptr) {
    LOG_ERROR << "Could not read PKCS12 data";
    return false;
  }

  auto stackx509_free = [](STACK_OF(X509) *stack) { sk_X509_pop_free(stack, X509_free); };

  StructGuard<EVP_PKEY> pkey(nullptr, EVP_PKEY_free);
  StructGuard<X509> x509_cert(nullptr, X509_free);
  StructGuard<STACK_OF(X509)> ca_certs(nullptr, stackx509_free);
  {
    EVP_PKEY *pk = nullptr;
    X509 *x509c = nullptr;
    STACK_OF(X509) *cacs = nullptr;
    if (PKCS12_parse(p12.get(), password.c_str(), &pk, &x509c, &cacs) == 0) {
      LOG_ERROR << "Could not parse PKCS12: " << ERR_error_string(ERR_get_error(), nullptr);
      return false;
    }
    pkey.reset(pk);
    x509_cert.reset(x509c);
    ca_certs.reset(cacs);
  }

  StructGuard<BIO> pkey_sink(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (pkey_sink == nullptr) {
    LOG_ERROR << "Could not create pkey buffer";
    return false;
  }
  if (PEM_write_bio_PrivateKey(pkey_sink.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    LOG_ERROR << "PEM_write_bio_PrivateKey failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }
  char *pkey_buf;
  long pkey_len = BIO_get_mem_data(pkey_sink.get(), &pkey_buf);
  *out_pkey = std::string(pkey_buf, static_cast<size_t>(pkey_len));

  StructGuard<BIO> cert_sink(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (cert_sink == nullptr) {
    LOG_ERROR << "Could not create cert buffer";
    return false;
  }
  if (PEM_write_bio_X509(cert_sink.get(), x509_cert.get()) != 1) {
    LOG_ERROR << "PEM_write_bio_X509 failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  StructGuard<BIO> ca_sink(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (ca_sink == nullptr) {
    LOG_ERROR << "Could not create ca buffer";
    return false;
  }
  for (int i = 0; i < sk_X509_num(ca_certs.get()); i++) {
    X509 *ca_cert = sk_X509_value(ca_certs.get(), i);
    if (PEM_write_bio_X509(ca_sink.get(), ca_cert) != 1 || PEM_write_bio_X509(cert_sink.get(), ca_cert) != 1) {
      LOG_ERROR << "PEM_write_bio_X509 for CA failed: " << ERR_error_string(ERR_get_error(), nullptr);
      return false;
    }
  }
  char *ca_buf;
  long ca_len = BIO_get_mem_data(ca_sink.get(), &ca_buf);
  *out_ca = std::string(ca_buf, static_cast<size_t>(ca_len));

  char *cert_buf;
  long cert_len = BIO_get_mem_data(cert_sink.get(), &cert_buf);
  *out_cert = std::string(cert_buf, static_cast<size_t>(cert_len));

  return true;
}

std::string Crypto::extractSubjectCN(const std::string &cert) {
  StructGuard<BIO> bio(BIO_new_mem_buf(const_cast<char *>(cert.c_str()), static_cast<int>(cert.size())), [](BIO *b) { BIO_free(b); });
  StructGuard<X509> x(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
  if (x == nullptr) {
    throw std::runtime_error("Could not parse certificate");
  }

  int len = X509_NAME_get_text_by_NID(X509_get_subject_name(x.get()), NID_commonName, nullptr, 0);
  if (len < 0) {
    throw std::runtime_error("Could not get CN from certificate");
  }
  boost::scoped_array<char> buf(new char[len + 1]);
  X509_NAME_get_text_by_NID(X509_get_subject_name(x.get()), NID_commonName, buf.get(), len + 1);
  return std::string(buf.get());
}

StructGuard<EVP_PKEY> Crypto::generateRSAKeyPairEVP(KeyType key_type) {
  int64_t bits;
  switch (key_type) {
    case KeyType::kRSA2048:
      bits = 2048;
      break;
    case KeyType::kRSA3072:
      bits = 3072;
      break;
    case KeyType::kRSA4096:
      bits = 4096;
      break;
    default:
      return {nullptr, EVP_PKEY_free};
  }
  return Crypto::generateRSAKeyPairEVP(bits);
}

StructGuard<EVP_PKEY> Crypto::generateRSAKeyPairEVP(int64_t bits) {
  if (bits < 31) {
    throw std::runtime_error("RSA key size can't be smaller than 31 bits");
  }

  StructGuard<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr || EVP_PKEY_keygen_init(ctx.get()) != 1) {
    throw std::runtime_error("EVP_PKEY_keygen_init failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), static_cast<int>(bits)) != 1) {
    throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &pkey) != 1) {
    throw std::runtime_error("EVP_PKEY_keygen failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }
  return StructGuard<EVP_PKEY>(pkey, EVP_PKEY_free);
}

bool Crypto::generateRSAKeyPair(KeyType key_type, std::string *public_key, std::string *private_key) {
  StructGuard<EVP_PKEY> pkey = generateRSAKeyPairEVP(key_type);
  if (pkey == nullptr) {
    return false;
  }

  StructGuard<BIO> pubkey_sink(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (pubkey_sink == nullptr || PEM_write_bio_PUBKEY(pubkey_sink.get(), pkey.get()) != 1) {
    LOG_ERROR << "PEM_write_bio_PUBKEY failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }
  char *pubkey_buf;
  long pubkey_len = BIO_get_mem_data(pubkey_sink.get(), &pubkey_buf);
  *public_key = std::string(pubkey_buf, static_cast<size_t>(pubkey_len));

  StructGuard<BIO> privkey_sink(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (privkey_sink == nullptr || PEM_write_bio_PrivateKey(privkey_sink.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    LOG_ERROR << "PEM_write_bio_PrivateKey failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }
  char *privkey_buf;
  long privkey_len = BIO_get_mem_data(privkey_sink.get(), &privkey_buf);
  *private_key = std::string(privkey_buf, static_cast<size_t>(privkey_len));
  return true;
}

bool Crypto::generateEDKeyPair(std::string *public_key, std::string *private_key) {
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> sk{};
  crypto_sign_keypair(pk.data(), sk.data());
  *public_key = boost::algorithm::hex(std::string(reinterpret_cast<char *>(pk.data()), crypto_sign_PUBLICKEYBYTES));
  *private_key = boost::algorithm::hex(std::string(reinterpret_cast<char *>(sk.data()), crypto_sign_SECRETKEYBYTES));
  return true;
}

bool Crypto::generateKeyPair(KeyType key_type, std::string *public_key, std::string *private_key) {
  if (key_type == KeyType::kED25519) {
    return Crypto::generateEDKeyPair(public_key, private_key);
  }
  return Crypto::generateRSAKeyPair(key_type, public_key, private_key);
}

bool Crypto::IsRsaKeyType(KeyType type) {
  switch (type) {
    case KeyType::kRSA2048:
    case KeyType::kRSA3072:
    case KeyType::kRSA4096:
      return true;
    default:
      return false;
  }
}

KeyType Crypto::IdentifyRSAKeyType(const std::string &public_key_pem) {
  StructGuard<BIO> bufio(BIO_new_mem_buf(public_key_pem.c_str(), static_cast<int>(public_key_pem.length())), [](BIO *b) { BIO_free(b); });
  if (bufio.get() == nullptr) {
    throw std::runtime_error("BIO_new_mem_buf failed");
  }
  StructGuard<EVP_PKEY> pkey(PEM_read_bio_PUBKEY(bufio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (pkey.get() == nullptr) {
    return KeyType::kUnknown;
  }

  int key_length = EVP_PKEY_bits(pkey.get());
  switch (key_length) {
    case 2048:
      return KeyType::kRSA2048;
    case 3072:
      return KeyType::kRSA3072;
    case 4096:
      return KeyType::kRSA4096;
    default:
      LOG_WARNING << "Weird key length: " << key_length;
      return KeyType::kUnknown;
  }
}

StructGuard<X509> Crypto::generateCert(int64_t rsa_bits, int days, const std::string &country, const std::string &state,
                                      const std::string &org, const std::string &cn, bool self_sign) {
  StructGuard<X509> certificate(X509_new(), X509_free);
  if (certificate.get() == nullptr) {
    throw std::runtime_error("X509_new failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  X509_set_version(certificate.get(), 2); // X509v3

  std::random_device urandom;
  std::uniform_int_distribution<> serial_dist(0, (1UL << 20) - 1);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial_dist(urandom));

  StructGuard<X509_NAME> subj(X509_NAME_new(), X509_NAME_free);
  if (subj.get() == nullptr) {
    throw std::runtime_error("X509_NAME_new failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (!country.empty()) {
    if (X509_NAME_add_entry_by_txt(subj.get(), "C", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(country.c_str()), -1, -1, 0) == 0) {
      throw std::runtime_error("X509_NAME_add_entry_by_txt failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
  }

  if (!state.empty()) {
    if (X509_NAME_add_entry_by_txt(subj.get(), "ST", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(state.c_str()), -1, -1, 0) == 0) {
      throw std::runtime_error("X509_NAME_add_entry_by_txt failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
  }

  if (!org.empty()) {
    if (X509_NAME_add_entry_by_txt(subj.get(), "O", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(org.c_str()), -1, -1, 0) == 0) {
      throw std::runtime_error("X509_NAME_add_entry_by_txt failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
  }

  assert(!cn.empty());
  if (X509_NAME_add_entry_by_txt(subj.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0) == 0) {
    throw std::runtime_error("X509_NAME_add_entry_by_txt failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (X509_set_subject_name(certificate.get(), subj.get()) == 0) {
    throw std::runtime_error("X509_set_subject_name failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  StructGuard<EVP_PKEY> certificate_pkey(Crypto::generateRSAKeyPairEVP(rsa_bits));
  if (X509_set_pubkey(certificate.get(), certificate_pkey.get()) == 0) {
    throw std::runtime_error("X509_set_pubkey failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) == nullptr ||
      X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60L * 60L * 24L * days) == nullptr) {
    throw std::runtime_error("X509_gmtime_adj failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (self_sign) {
    const EVP_MD *cert_digest = EVP_sha256();
    if (X509_sign(certificate.get(), certificate_pkey.get(), cert_digest) == 0) {
      throw std::runtime_error("X509_sign failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
    LOG_INFO << "Successfully self-signed the generated certificate. This should not be used in production!";
  }

  return certificate;
}

void Crypto::signCert(const std::string &cacert_path, const std::string &capkey_path, X509 *certificate) {
  std::string cacert_contents = Utils::readFile(cacert_path);
  StructGuard<BIO> bio_in_cacert(BIO_new_mem_buf(cacert_contents.c_str(), static_cast<int>(cacert_contents.size())), [](BIO *b) { BIO_free(b); });
  StructGuard<X509> ca_certificate(PEM_read_bio_X509(bio_in_cacert.get(), nullptr, nullptr, nullptr), X509_free);
  if (ca_certificate.get() == nullptr) {
    throw std::runtime_error("Reading CA certificate failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  std::string capkey_contents = Utils::readFile(capkey_path);
  StructGuard<BIO> bio_in_capkey(BIO_new_mem_buf(capkey_contents.c_str(), static_cast<int>(capkey_contents.size())), [](BIO *b) { BIO_free(b); });
  StructGuard<EVP_PKEY> ca_privkey(PEM_read_bio_PrivateKey(bio_in_capkey.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (ca_privkey.get() == nullptr) {
    throw std::runtime_error("PEM_read_bio_PrivateKey failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  X509_NAME *ca_subj = X509_get_subject_name(ca_certificate.get());
  if (ca_subj == nullptr || X509_set_issuer_name(certificate, ca_subj) == 0) {
    throw std::runtime_error("X509_set_issuer_name failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  const EVP_MD *cert_digest = EVP_sha256();
  if (X509_sign(certificate, ca_privkey.get(), cert_digest) == 0) {
    throw std::runtime_error("X509_sign failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }
}

void Crypto::serializeCert(std::string *pkey, std::string *cert, X509 *certificate) {
  StructGuard<BIO> privkey_file(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (privkey_file == nullptr) {
    throw std::runtime_error("BIO_new failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  StructGuard<EVP_PKEY> certificate_pkey(X509_get_pubkey(certificate), EVP_PKEY_free);
  if (certificate_pkey == nullptr) {
    throw std::runtime_error("X509_get_pubkey failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }

  if (PEM_write_bio_PrivateKey(privkey_file.get(), certificate_pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
    throw std::runtime_error("PEM_write_bio_PrivateKey failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }
  char *privkey_buf;
  long privkey_len = BIO_get_mem_data(privkey_file.get(), &privkey_buf);
  *pkey = std::string(privkey_buf, static_cast<size_t>(privkey_len));

  StructGuard<BIO> cert_file(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (cert_file == nullptr) {
    throw std::runtime_error("BIO_new failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }
  if (PEM_write_bio_X509(cert_file.get(), certificate) != 1) {
    throw std::runtime_error("PEM_write_bio_X509 failed: " + std::string(ERR_error_string(ERR_get_error(), nullptr)));
  }
  char *cert_buf;
  long cert_len = BIO_get_mem_data(cert_file.get(), &cert_buf);
  *cert = std::string(cert_buf, static_cast<size_t>(cert_len));
}

MultiPartHasher::Ptr MultiPartHasher::create(Hash::Type hash_type) {
  switch (hash_type) {
    case Hash::Type::kSha256:
      return std::make_shared<MultiPartSHA256Hasher>();
    case Hash::Type::kSha512:
      return std::make_shared<MultiPartSHA512Hasher>();
    default:
      LOG_ERROR << "Unsupported type of hashing: " << Hash::TypeString(hash_type);
      return nullptr;
  }
}

Hash Hash::generate(Type type, const std::string &data) {
  std::string hash;
  switch (type) {
    case Type::kSha256:
      hash = boost::algorithm::hex(Crypto::sha256digest(data));
      break;
    case Type::kSha512:
      hash = boost::algorithm::hex(Crypto::sha512digest(data));
      break;
    default:
      throw std::invalid_argument("Unsupported hash type");
  }
  return Hash(type, hash);
}

Hash::Hash(const std::string &type, const std::string &hash) : hash_(boost::algorithm::to_upper_copy(hash)) {
  if (type == "sha512") {
    type_ = Hash::Type::kSha512;
  } else if (type == "sha256") {
    type_ = Hash::Type::kSha256;
  } else {
    type_ = Hash::Type::kUnknownAlgorithm;
  }
}

Hash::Hash(Type type, const std::string &hash) : type_(type), hash_(boost::algorithm::to_upper_copy(hash)) {}

bool Hash::operator==(const Hash &other) const { return type_ == other.type_ && hash_ == other.hash_; }

std::string Hash::TypeString(Type type) {
  switch (type) {
    case Type::kSha256:
      return "sha256";
    case Type::kSha512:
      return "sha512";
    default:
      return "unknown";
  }
}

std::string Hash::TypeString() const { return TypeString(type_); }

Hash::Type Hash::type() const { return type_; }

std::ostream &operator<<(std::ostream &os, const Hash &h) {
  os << "Hash: " << h.hash_;
  return os;
}
