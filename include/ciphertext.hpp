#ifndef CIPHERTEXT_HPP
#define CIPHERTEXT_HPP

#include <vector>
#include <cstdint>

struct Ciphertext {
  std::vector<uint8_t> iv;
  std::vector<uint8_t> data;
  std::vector<uint8_t> tag;
};

#endif