#include "p11engine.h"

#include <array>
#include <utility>
#include <vector>

#include <libp11.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/format.hpp>

#include "crypto.h"
#include "utilities/config_utils.h"
#include "utilities/utils.h"

P11EngineGuard::instance* P11EngineGuard::instance = nullptr;
int ref_counter = 0;

P11ContextWrapper::P11ContextWrapper(const boost::filesystem::path& module) {
  if (module.empty()) {
    ctx = nullptr;
    return;
  }
  ctx = PKCS11_CTX_new();
  if (PKCS11_CTX_load(ctx, module.c_str()) != 0) {
    PKCS11_CTX_free(ctx);
    ctx = nullptr;
    LOG_ERROR << "Couldn't load PKCS11 module " << module.string() << ": "
              << ERR_error_string(ERR_get_error(), nullptr);
    throw std::runtime_error("PKCS11 error");
  }
}

P11ContextWrapper::~P11ContextWrapper() {
  if (ctx != nullptr) {
    PKCS11_CTX_unload(ctx);
    PKCS11_CTX_free(ctx);
  }
}

P11SlotsWrapper::P11SlotsWrapper(PKCS11_ctx_st* ctx_in) {
  ctx = ctx_in;
  if (ctx == nullptr) {
    wslots_ = nullptr;
    nslots = 0;
    return;
  }
  if (PKCS11_enumerate_slots(ctx, &wslots_, &nslots) != 0) {
    LOG_ERROR << "Couldn't enumerate slots: " << ERR_error_string(ERR_get_error(), nullptr);
    throw std::runtime_error("PKCS11 error");
  }
}

P11SlotsWrapper::~P11SlotsWrapper() {
  if ((wslots_ != nullptr) && (nslots != 0U)) {
    PKCS11_release_all_slots(ctx, wslots_, nslots);
  }
}

P11Engine::P11Engine(P11Config config) : config_(std::move(config)), ctx_(config_.module), P11slots_(ctx_.get()) {
#ifdef BUILD_P11
  if (config_.module.empty()) {
    return;
  }

  PKCS11_SLOT* slot = PKCS11_find_token(ctx_.get(), P11slots_.get_slots(), P11slots_.get_nslots());
  if ((slot == nullptr) || (slot->token == nullptr)) {
    throw std::runtime_error("Couldn't find pkcs11 token");
  }

  LOG_DEBUG << "Slot manufacturer......: " << slot->manufacturer;
  LOG_DEBUG << "Slot description.......: " << slot->description;
  LOG_DEBUG << "Slot token label.......: " << slot->token->label;
  LOG_DEBUG << "Slot token manufacturer: " << slot->token->manufacturer;
  LOG_DEBUG << "Slot token model.......: " << slot->token->model;
  LOG_DEBUG << "Slot token serialnr....: " << slot->token->serialnr;

  uri_prefix_ = std::string("pkcs11:serial=") + slot->token->serialnr + ";pin-value=" + config_.pass + ";id=%";

  const boost::filesystem::path pkcs11Path = findPkcsLibrary();
  LOG_INFO << "Loading PKCS#11 engine library: " << pkcs11Path.string();

  ENGINE *engine = ENGINE_by_id("dynamic");
  if (engine == nullptr) {
    throw std::runtime_error("SSL pkcs11 engine initialization failed");
  }

  try {
    if (ENGINE_ctrl_cmd_string(engine, "SO_PATH", pkcs11Path.c_str(), 0) == 0) {
      throw std::runtime_error(std::string("P11 engine command failed: SO_PATH ") + pkcs11Path.string());
    }

    if (ENGINE_ctrl_cmd_string(engine, "ID", "pkcs11", 0) == 0) {
      throw std::runtime_error("P11 engine command failed: ID pksc11");
    }

    if (ENGINE_ctrl_cmd_string(engine, "LIST_ADD", "1", 0) == 0) {
      throw std::runtime_error("P11 engine command failed: LIST_ADD 1");
    }

    if (ENGINE_ctrl_cmd_string(engine, "LOAD", nullptr, 0) == 0) {
      throw std::runtime_error("P11 engine command failed: LOAD");
    }

    if (ENGINE_ctrl_cmd_string(engine, "MODULE_PATH", config_.module.c_str(), 0) == 0) {
      throw std::runtime_error(std::string("P11 engine command failed: MODULE_PATH ") + config_.module.string());
    }

    if (ENGINE_ctrl_cmd_string(engine, "PIN", config_.pass.c_str(), 0) == 0) {
      throw std::runtime_error(std::string("P11 engine command failed: PIN"));
    }

    if (ENGINE_init(engine) == 0) {
      throw std::runtime_error("P11 engine initialization failed");
    }
  } catch (const std::runtime_error& exc) {
    ENGINE_free(engine);
    throw;
  }

  ssl_engine_ = engine;
#endif
}

boost::filesystem::path P11Engine::findPkcsLibrary() {
  static const boost::filesystem::path engine_path = PKCS11_ENGINE_PATH;

  if (!boost::filesystem::exists(engine_path)) {
    LOG_ERROR << "PKCS11 engine not available (" << engine_path << ")";
    return "";
  }

  return engine_path;
}

PKCS11_slot_st* P11Engine::findTokenSlot() const {
  PKCS11_slot_st* slot = PKCS11_find_token(ctx_.get(), P11slots_.get_slots(), P11slots_.get_nslots());
  if ((slot == nullptr) || (slot->token == nullptr)) {
    LOG_ERROR << "Couldn't find a token";
    return nullptr;
  }
  int rv;
  PKCS11_is_logged_in(slot, 1, &rv);
  if (rv == 0) {
    if (PKCS11_open_session(slot, 1) != 0) {
      LOG_ERROR << "Error creating rw session in to the slot: " << ERR_error_string(ERR_get_error(), nullptr);
    }

    if (PKCS11_login(slot, 0, config_.pass.c_str()) != 0) {
      LOG_ERROR << "Error logging in to the token: " << ERR_error_string(ERR_get_error(), nullptr);
      return nullptr;
    }
  }
  return slot;
}

bool P11Engine::readUptanePublicKey(std::string* key_out) {
  if (config_.module.empty()) {
    return false;
  }
  if ((config_.uptane_key_id.length() % 2) != 0U) {
    return false; // id is a hex string
  }

  PKCS11_slot_st* slot = findTokenSlot();
  if (slot == nullptr) {
    return false;
  }

  PKCS11_KEY* keys;
  unsigned int nkeys;
  int rc = PKCS11_enumerate_public_keys(slot->token, &keys, &nkeys);
  if (rc < 0) {
    LOG_ERROR << "Error enumerating public keys in PKCS11 device: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }
  PKCS11_KEY* key = nullptr;
  {
    std::vector<unsigned char> id_hex;
    boost::algorithm::unhex(config_.uptane_key_id, std::back_inserter(id_hex));

    for (unsigned int i = 0; i < nkeys; i++) {
      if ((keys[i].id_len == config_.uptane_key_id.length() / 2) &&
          (memcmp(keys[i].id, id_hex.data(), config_.uptane_key_id.length() / 2) == 0)) {
        key = &keys[i];
        break;
      }
    }
  }
  if (key == nullptr) {
    LOG_ERROR << "Requested public key was not found";
    return false;
  }
  StructGuard<EVP_PKEY> evp_key(PKCS11_get_public_key(key), EVP_PKEY_free);
  StructGuard<BIO> mem(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (mem.get() == nullptr || PEM_write_bio_PUBKEY(mem.get(), evp_key.get()) != 1) {
    LOG_ERROR << "PEM_write_bio_PUBKEY failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  char* pem_key = nullptr;
  long length = BIO_get_mem_data(mem.get(), &pem_key);
  key_out->assign(pem_key, static_cast<size_t>(length));

  return true;
}

bool P11Engine::generateUptaneKeyPair() {
  PKCS11_slot_st* slot = findTokenSlot();
  if (slot == nullptr) {
    return false;
  }

  std::vector<unsigned char> id_hex;
  boost::algorithm::unhex(config_.uptane_key_id, std::back_inserter(id_hex));

  StructGuard<EVP_PKEY> pkey = Crypto::generateRSAKeyPairEVP(KeyType::kRSA2048);
  if (pkey == nullptr) {
    LOG_ERROR << "Error generating keypair on the device: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  if (PKCS11_store_private_key(slot->token, pkey.get(), nullptr, id_hex.data(), id_hex.size()) != 0) {
    LOG_ERROR << "Could not store private key on the token";
    return false;
  }
  if (PKCS11_store_public_key(slot->token, pkey.get(), nullptr, id_hex.data(), id_hex.size()) != 0) {
    LOG_ERROR << "Could not store public key on the token";
    return false;
  }

  return true;
}

bool P11Engine::readTlsCert(std::string* cert_out) const {
  const std::string& id = config_.tls_clientcert_id;

  if (config_.module.empty()) {
    return false;
  }
  if ((id.length() % 2) != 0U) {
    return false; // id is a hex string
  }

  PKCS11_slot_st* slot = findTokenSlot();
  if (slot == nullptr) {
    return false;
  }

  PKCS11_CERT* certs;
  unsigned int ncerts;
  int rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
  if (rc < 0) {
    LOG_ERROR << "Error enumerating certificates in PKCS11 device: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  PKCS11_CERT* cert = nullptr;
  {
    std::vector<unsigned char> id_hex;
    boost::algorithm::unhex(id, std::back_inserter(id_hex));

    for (unsigned int i = 0; i < ncerts; i++) {
      if ((certs[i].id_len == id.length() / 2) && (memcmp(certs[i].id, id_hex.data(), id.length() / 2) == 0)) {
        cert = &certs[i];
        break;
      }
    }
  }
  if (cert == nullptr) {
    LOG_ERROR << "Requested certificate was not found";
    return false;
  }
  StructGuard<BIO> mem(BIO_new(BIO_s_mem()), [](BIO *b) { BIO_free(b); });
  if (mem.get() == nullptr || PEM_write_bio_X509(mem.get(), cert->x509) != 1) {
    LOG_ERROR << "PEM_write_bio_X509 failed: " << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }

  char* pem_key = nullptr;
  long length = BIO_get_mem_data(mem.get(), &pem_key);
  cert_out->assign(pem_key, static_cast<size_t>(length));

  return true;
}