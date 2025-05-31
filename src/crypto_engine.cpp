#include "crypto_engine.hpp"

CryptoEngine::CryptoEngine()
{
    if (!libsodiumInitialized)
    {
        if (sodium_init() < 0)
        {
            throw new std::runtime_error("libsodium could not be initialized on CryptoEngine declaration.");
        }
        libsodiumInitialized = true;
    }
}

std::vector<uint8_t> CryptoEngine::deriveKey(const std::string &passphrase,
                                             std::vector<uint8_t> &outSalt)
{
    // Preparing the output salt with the correct size.
    outSalt.resize(saltSize);

    // Fill outSalt with random bytes.
    randombytes_buf(outSalt.data(), saltSize);

    // Allocate the output key buffer with the previously specified keySize.
    std::vector<uint8_t> key(keySize);

    //    Perform Argon2id KDF
    //    - out:       key.data()
    //    - outlen:    keySize (32)
    //    - passwd:    passphrase.c_str()
    //    - passwdlen: passphrase.size()
    //    - salt:      outSalt.data() (16 bytes)
    //    - opslimit:  timeCost (e.g. 2)
    //    - memlimit:  memoryCost * 1024 (because memoryCost is in KiB)
    //    - alg:       crypto_pwhash_ALG_ARGON2ID13

    if (crypto_pwhash(
            key.data(),
            static_cast<unsigned long long>(keySize),
            passphrase.c_str(),
            static_cast<unsigned long long>(passphrase.size()),
            outSalt.data(),
            static_cast<unsigned long long>(timeCost),
            static_cast<size_t>(memoryCost * 1024),
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        // If it returns non-zero, the KDF failed (likely out of memory)
        throw std::runtime_error("Argon2id key derivation failed");
    }

    return key;
}

Ciphertext CryptoEngine::encrypt(const std::vector<uint8_t> &key,
                                 const std::string &plaintext)
{
    // Generate a fresh 12-byte nonce (IV)
    std::vector<uint8_t> iv(ivSize);
    randombytes_buf(iv.data(), ivSize);

    // Allocate buffers for ciphertext (same length as plaintext) and tag (16 bytes)
    std::vector<uint8_t> data(plaintext.size());
    std::vector<uint8_t> tag(tagSize);

    // Perform AEAD encryption (detached mode)
    unsigned long long actualTagLen = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        data.data(),                       // ciphertext output
        tag.data(),                        // authentication tag output
        &actualTagLen,                     // actual tag length
        reinterpret_cast<const unsigned char*>(plaintext.data()), // plaintext input
        static_cast<unsigned long long>(plaintext.size()),       // plaintext length
        nullptr,                            // associated data (none)
        0ULL,                               // associated data length
        nullptr,                            // nsec (unused)
        iv.data(),                          // nonce
        key.data()                          // 256-bit key
    );

    
    if (ret != 0 || actualTagLen != tagSize) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }

    // Package IV, ciphertext, and tag into a Ciphertext struct and return it
    Ciphertext result;
    result.iv   = std::move(iv);
    result.data = std::move(data);
    result.tag  = std::move(tag);
    return result;
}

std::string CryptoEngine::decrypt(const std::vector<uint8_t>& key,
                                  const Ciphertext& blob)
{
    // Allocate a buffer for the decrypted plaintext (same length as ciphertext)
    std::vector<uint8_t> decrypted(blob.data.size());

    // Perform AEAD decryption (detached mode)
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        decrypted.data(),                                 // plaintext output
        nullptr,                                          // nsec (unused, must be NULL)
        blob.data.data(),                                 // ciphertext input
        static_cast<unsigned long long>(blob.data.size()),// ciphertext length
        blob.tag.data(),                                  // authentication tag
        nullptr,                                          // associated data (none)
        0ULL,                                             // associated data length
        blob.iv.data(),                                   // nonce (12 bytes)
        key.data()                                        // 256-bit key
    );

    if (ret != 0) {
        // Authentication failed (wrong key, tampered data, or invalid parameters)
        throw std::runtime_error("ChaCha20-Poly1305 decryption failed or authentication tag invalid");
    }

    // 3) Convert the decrypted bytes into a std::string
    std::string plaintext(reinterpret_cast<const char*>(decrypted.data()),
                          decrypted.size());

    // 4) Return the recovered plaintext
    return plaintext;
}