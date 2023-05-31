#ifndef __OAEP_H
#define __OAEP_H

#include <string>
#include <stdexcept>
#include <iostream>

namespace OAEP {
    std::string pad(std::string message, uint16_t keyLength);
};

#endif
