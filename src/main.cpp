#include "crypto_engine.hpp"
#include <iostream>

int main() {
    try {
        CryptoEngine engine;

        // 1) Derive a key (and a random salt we’ll ignore for this test)
        std::vector<uint8_t> salt;
        auto key = engine.deriveKey("myMasterPassword", salt);

        // 2) Encrypt a sample plaintext
        std::string original = "SuperSecret123!";
        Ciphertext ct = engine.encrypt(key, original);

        std::cout << "Encrypted “" << original << "” → "
                  << ct.data.size() << " bytes ciphertext, "
                  << ct.tag.size()  << " bytes tag\n";

        // 3) Decrypt using the same key and blob
        std::string recovered = engine.decrypt(key, ct);

        std::cout << "Decrypted back to: “" << recovered << "”\n";

        if (recovered == original) {
            std::cout << "✅ Round-trip successful!\n";
        } else {
            std::cout << "❌ Decryption output does not match original.\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}