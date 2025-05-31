#ifndef CRYPTO_ENGINE_HPP
#define CRYPTO_ENGINE_HPP

#include <iostream>
#include <cstdint>
#include <vector>
#include <sodium.h>

#include "ciphertext.hpp"


class CryptoEngine {
private:
  // ————————————————
  // KDF parameters (Argon2 only)
  // ————————————————
  std::size_t saltSize      = 16;      // bytes
  std::uint32_t memoryCost  = 32 * 1024; // KiB (≈32 MiB)
  std::uint32_t timeCost    = 2;       // passes over memory
  std::uint32_t parallelism = 2;       // lanes (threads)

// AEAD parameters
std::size_t keySize = crypto_aead_chacha20poly1305_ietf_KEYBYTES;   // 32 bytes
std::size_t ivSize  = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;  // 12 bytes
std::size_t tagSize = crypto_aead_chacha20poly1305_ietf_ABYTES;     // 16 bytes
  
  bool libsodiumInitialized = false;

public:

  CryptoEngine();

  // Derives a 256-bit key from passphrase + salt
  // Generates a 'saltSize'-byte random salt
  std::vector<uint8_t> deriveKey(const std::string& passphrase,
                                 std::vector<uint8_t>& outSalt);

  // Encrypt plaintext → Ciphertext struct (iv, data, tag)
  Ciphertext encrypt(const std::vector<uint8_t>& key,
                     const std::string& plaintext);

  // Decrypt Ciphertext struct → plaintext (or throw on auth failure)
  std::string decrypt(const std::vector<uint8_t>& key,
                      const Ciphertext& blob);
};


#endif
