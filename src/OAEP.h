#ifndef __OAEP_H
#define __OAEP_H

#include <iostream>
#include <random>
#include <stdexcept>
#include <string>

#ifdef DEBUG_TESTING
#include <iomanip>
#endif

namespace OAEP {
#define HASH_BYTES 15 // My hashing algorithm outputs a fixed 15 bytes

std::string MGF1(std::string seed, uint16_t maskLength);
std::string pad(std::string message, uint32_t pLen, const char* P, uint32_t emLen);
std::string unpad(std::string padded, uint32_t pLen, const char* P);
} // namespace OAEP

#endif
