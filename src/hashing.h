#include <string.h>
#include <cstdio>
#include <cstdint>

namespace Hashing {
    #define STATE_BUF_LEN 15
    #define PASSES 16
    #define RING_BUF_INDEX(i) (signed int)(i) % STATE_BUF_LEN < 0 ? (signed int)(i) % STATE_BUF_LEN + STATE_BUF_LEN : (signed int)(i) % STATE_BUF_LEN

    void hash(char output[STATE_BUF_LEN], const char* input, const int length);
}
