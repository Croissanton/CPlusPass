# CPlusPass

**CPlusPass** is a simple command-line password manager written in C++ using libsodium for cryptographic operations. It allows you to securely store and retrieve a single secret (e.g., a password) encrypted under a master passphrase.

---

![Retrieve Password](https://github.com/Croissanton/CPlusPass/blob/main/images/RetrievePassword.png)

![Store Password](https://github.com/Croissanton/CPlusPass/blob/main/images/StorePassword.png)

---

## Features

* **Master Passphrase**: Derives a strong 256-bit encryption key from your master passphrase using Argon2id (memory-hard KDF).
* **Authenticated Encryption**: Encrypts the secret using ChaCha20-Poly1305 (IETF) AEAD for both confidentiality and integrity.
* **Secure Storage**: Persists the salt, nonce (IV), ciphertext, and authentication tag in a binary vault file.
* **Simple CLI Interface**: Allows storing (`store`) or retrieving (`retrieve`) the secret via user prompts.

---

## Project Structure

```
CPlusPass/
├── CMakeLists.txt          # Build configuration
├── include/                # Public headers
│   ├── ciphertext.hpp      # Definition of Ciphertext struct
│   ├── crypto_engine.hpp   # CryptoEngine class declaration
│   ├── storage.hpp         # Storage class declaration
│   └── vault.hpp           # Vault class declaration
├── src/                    # Implementation files
│   ├── ciphertext.cpp      # (omitted if no helpers; otherwise serialize helpers)
│   ├── crypto_engine.cpp   # CryptoEngine implementations
│   ├── storage.cpp         # Storage implementations
│   ├── vault.cpp           # Vault implementations
│   └── main.cpp            # CLI entry point
└── README.md               # This file
```

---

## Prerequisites

* **C++17 (or later)**: The project targets C++23.
* **CMake (>= 3.15)**: Used to generate build files.
* **libsodium**: Provides cryptographic primitives (Argon2id, ChaCha20-Poly1305, secure random).

On Ubuntu/Debian, install dependencies with:

```bash
sudo apt update
sudo apt install build-essential cmake libsodium-dev
```

On macOS (with Homebrew):

```bash
brew install cmake libsodium
```

---

## Building

1. **Clone the repository**:

   ```bash
   git clone https://github.com/croissanton/CPlusPass.git
   cd CPlusPass
   ```

2. **Create and navigate to a build directory**:

   ```bash
   mkdir build && cd build
   ```

3. **Generate build files with CMake (using Ninja or Makefiles)**:

   ```bash
   # For Ninja (recommended):
   cmake -G Ninja ..
   # Or for Makefiles:
   cmake -G "Unix Makefiles" ..
   ```

4. **Build the project**:

   ```bash
   cmake --build .
   ```

   This produces an executable named `CPlusPass` in the build directory.

---

## Usage

Run the `CPlusPass` executable without arguments. You will be prompted to choose between storing or retrieving a secret.

```bash
./CPlusPass
```

* **Store a secret**:

  1. Enter `s` (or `S`) when prompted.
  2. Enter your master passphrase (no-echo recommended, but CLI currently echoes input).
  3. Enter the secret you wish to store (e.g., a password or API key).
  4. The vault file (`vault.bin`) is created/overwritten with the encrypted data.

* **Retrieve a secret**:

  1. Enter `r` (or `R`) when prompted.
  2. Enter your master passphrase.
  3. If the passphrase is correct and the data is intact, the decrypted secret is printed.
  4. If the passphrase is wrong or data is corrupted, an error is shown.

---

## Detailed Components

### CryptoEngine (include/crypto\_engine.hpp & src/crypto\_engine.cpp)

Provides:

* `deriveKey(passphrase, outSalt)`: Uses Argon2id to derive a 32-byte key and outputs a 16-byte salt.
* `encrypt(key, plaintext)`: Uses ChaCha20-Poly1305 to encrypt and authenticate `plaintext`, returns a `Ciphertext { iv, data, tag }`.
* `decrypt(key, Ciphertext)`: Verifies and decrypts, returning the original plaintext or throwing an error on auth failure.

### Storage (include/storage.hpp & src/storage.cpp)

Handles:

* `write(salt, Ciphertext)`: Writes salt (16B), IV length & IV, ciphertext length & ciphertext, tag length & tag to a binary file.
* `read()`: Reads and returns `<salt, Ciphertext>` from the vault file, throwing errors if the file is missing or malformed.

### Vault (include/vault.hpp & src/vault.cpp)

Orchestrates:

* `storeSecret(passphrase, secret)`: Derives key+salt, encrypts secret, and calls `Storage::write`.
* `retrieveSecret(passphrase)`: Reads `<salt, Ciphertext>` via `Storage::read`, re-derives key, and decrypts via `CryptoEngine::decrypt`.

### Main (src/main.cpp)

Provides a simple CLI loop to store or retrieve the secret by interacting with `Vault`.

---

## Security Considerations

* **Salt and Nonce**: Each store operation uses a fresh random salt (16 bytes) for Argon2 and a fresh random nonce (12 bytes) for ChaCha20-Poly1305.
* **Argon2 Parameters**: Default settings are 32 MiB memory, 2 passes, and 2 lanes. Adjust in `CryptoEngine` if you need different KDF strength.
* **Authentication**: If ciphertext or tag is tampered with, decryption throws an error.
* **Passphrase Echo**: Currently your passphrase is read via `std::getline`, which echoes input. For production, integrate a no-echo library call (e.g. `getpass()` on Unix) to hide passphrase on entry.
* **Memory Zeroing**: Consider wiping sensitive data (`passphrase`, `key`, `salt`) from memory after use with `sodium_memzero()`.

---

## Extending the Project

* **Multiple Entries**: Instead of storing a single secret, extend `Vault` to support a map of `label → (salt, Ciphertext)`, serialize a simple database, etc.
* **Encryption Algorithms**: Add command-line flags to switch between ChaCha20-Poly1305 and AES-GCM (with runtime `is_available()` checks).
* **Configuration**: Allow customizing Argon2 parameters (memory, timeCost, parallelism) via a config file or CLI flags.
* **Tests**: Introduce unit tests (e.g., using Google Test or Catch2) for each module (`CryptoEngine`, `Storage`, `Vault`).
* **Improved CLI**: Use a library like `argparse` or `CLI11` to support subcommands, no-echo passphrase, and flags.
* **GUI Frontend with Qt**:  Create a graphical interface using Qt.

---

## License

This project is provided under the MIT license. See `LICENSE` for details.
