#ifndef __STR_ASM_H
#define __STR_ASM_H

#include <mutex>
#include <string>
#include <vector>

/**
 * @brief A class to assemble a string from multiple threads.
 * @note Used in src/RSA/RSA-methods.cpp for parallelization of RSA encryption&decryption with chunks.
 * 
*/
class StringAssembler {
    private:
    std::vector<std::string> data;
    size_t totalStringLength = 0;
    mutable std::mutex mtx; // Only need to prevent concurrent writes to the `data` vector, not reads.

    public:
    StringAssembler(size_t sz); // Must pass number of strings. This is more efficient than checking the index every time and potentially resizing.
    void insertString(size_t idx, const std::string s); // Copied since threads will call the `std::string`s destructor before `assembleFinalString` is called from the main thread.
    std::string assembleFinalString(); // Called once by the main thread after all threads have finished writing to the `data` vector.
};

#endif