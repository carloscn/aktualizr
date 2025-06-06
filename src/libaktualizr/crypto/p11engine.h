#ifndef P11ENGINE_H_
#define P11ENGINE_H_

#include <memory>

#include "libaktualizr/config.h"

#ifdef BUILD_P11
#include <openssl/engine.h>
#include <openssl/err.h>
#endif

#include "gtest/gtest_prod.h"
#include "logging/logging.h"

class P11ContextWrapper {
 public:
  explicit P11ContextWrapper(const boost::filesystem::path &module);
  ~P11ContextWrapper();
  P11ContextWrapper(const P11ContextWrapper &) = delete;
  P11ContextWrapper &operator=(const P11ContextWrapper &) = delete;
  PKCS11_ctx_st *get() const { return ctx; }

 private:
  PKCS11_ctx_st *ctx;
};

class P11SlotsWrapper {
 public:
  explicit P11SlotsWrapper(PKCS11_ctx_st *ctx_in);
  ~P11SlotsWrapper();
  P11SlotsWrapper(const P11SlotsWrapper &) = delete;
  P11SlotsWrapper &operator=(const P11SlotsWrapper &) = delete;
  PKCS11_slot_st *get_slots() const { return wslots_; }
  unsigned int get_nslots() const { return nslots; }

 private:
  PKCS11_ctx_st *ctx;
  PKCS11_slot_st *wslots_;
  unsigned int nslots;
};

class P11EngineGuard;

class P11Engine {
 public:
  P11Engine(const P11Engine &) = delete;
  P11Engine &operator=(const P11Engine &) = delete;

  virtual ~P11Engine() {
#ifdef BUILD_P11
    if (ssl_engine_ != nullptr) {
      ENGINE_free(ssl_engine_);
    }
#endif
  }

#ifdef BUILD_P11
  ENGINE *getEngine() { return ssl_engine_; }
#else
  void *getEngine() { return nullptr; }
#endif
  std::string getUptaneKeyId() const { return uri_prefix_ + config_.uptane_key_id; }
  std::string getTlsCacertId() const { return uri_prefix_ + config_.tls_cacert_id; }
  std::string getTlsPkeyId() const { return uri_prefix_ + config_.tls_pkey_id; }
  std::string getTlsCertId() const { return uri_prefix_ + config_.tls_clientcert_id; }
  bool readUptanePublicKey(std::string *key_out);
  bool readTlsCert(std::string *cert_out) const;
  bool generateUptaneKeyPair();

 private:
  const P11Config config_;
#ifdef BUILD_P11
  ENGINE *ssl_engine_{nullptr};
#else
  void *ssl_engine_{nullptr};
#endif
  std::string uri_prefix_;
  P11ContextWrapper ctx_;
  P11SlotsWrapper slots_;

  static boost::filesystem::path findPkcsLibrary();
  PKCS11_slot_st *findTokenSlot() const;

  explicit P11Engine(P11Config config);

  friend class P11EngineGuard;
  FRIEND_TEST(crypto, findPkcsLibrary);
  FRIEND_TEST(crypto, sign_verify_rsa_p11);
  FRIEND_TEST(KeyManager, AllTestsPkcs11);
};

class P11EngineGuard {
 public:
  explicit P11EngineGuard(const P11Config &config) {
#ifdef BUILD_P11
    if (instance == nullptr) {
      instance = new P11Engine(config);
    }
    ++ref_counter;
#else
    (void)config; // Suppress unused parameter warning
#endif
  };
  ~P11EngineGuard() {
#ifdef BUILD_P11
    if (ref_counter != 0) {
      --ref_counter;
    }
    if (ref_counter == 0) {
      delete instance;
      instance = nullptr;
    }
#endif
  }
  P11Engine *operator->() const { return instance; }

 private:
  static P11Engine *instance;
  static int ref_counter;
};

#endif