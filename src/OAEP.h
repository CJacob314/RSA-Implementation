#ifndef __OAEP_H
#define __OAEP_H

#include <string>
#include <stdexcept>
#include <iostream>
#include <random>
#include <arpa/inet.h>

#ifdef DEBUG_TESTING
#include <iomanip>
#endif

namespace OAEP {
    #define HASH_BYTES 15 // My hashing algorithm outputs a fixed 15 bytes

    std::string MGF1(std::string seed, uint16_t maskLength);
    std::string pad(const std::string& message, uint32_t k);
    std::string unpad(const std::string& EM, uint32_t k);
}

#endif
