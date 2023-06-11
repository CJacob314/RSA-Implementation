#include "../hashing.h"

namespace Hashing {

    namespace { // Anonymous namespace to hide these variables and functions from the end-user

        unsigned char state[STATE_BUF_LEN];
        uint8_t COMPRESSION_SHIFTS[5] = {5, 3, 5, 3, 5};

        uint8_t stateDefault[STATE_BUF_LEN] = {0xBA, 0x23, 0x8C, 0x4E, 0x38, 0x4D, 0xC1, 0xCA, 0xA1, 0xA4, 0x78, 0xFF, 0x5F, 0xCE, 0xF7};

        void clearState(){
            memcpy((void*)state, (const void*)&stateDefault, STATE_BUF_LEN);
        }

        unsigned char* padInput(const char* input, const uint32_t length, uint32_t& newLength, bool& padded){
            uint32_t paddedLength = 512 - (length % 512);
            padded = false;

            if(!paddedLength) // No need to pad if already a multiple of 512
                return (unsigned char*)input;
            
            unsigned char* paddedInput = new unsigned char[newLength = (length + paddedLength)];

            memcpy(paddedInput, input, length);

            // Pad with zeroes, finishing with the original length to prevent collisions
            memset(paddedInput + length, 0x00, paddedLength);
            memcpy(paddedInput + length + paddedLength - 4, &length, 4);

            padded = true;
            return paddedInput;
        }
    }

    void hash(char output[STATE_BUF_LEN], const char* input, const int length){
        clearState();

        uint32_t newLength = 0;
        bool padded;
        unsigned char* paddedInput = padInput(input, length, newLength, padded);

        unsigned char lbyte = 0x57; // Initalized to 0x57 to start, why not.
        for(uint8_t p = 0; p < PASSES; p++){
            
            for(uint32_t i = 0; i < newLength; i++){
                unsigned char cbyte = paddedInput[i];

                // Overflows in the state-buffer are INTENTIONAL to make reversal SLIGHTLY more difficult
                // The below LONG array access of paddedInput is a replica of the RING_BUF_INDEX function but with loop around the length of paddedInput, instead of the state buffer.
                state[RING_BUF_INDEX(i)] += (cbyte ^ (lbyte)) + paddedInput[(signed int)(i) % newLength < 0 ? (signed int)(i) % newLength + newLength : (signed int)(i) % newLength];

                // Below lines are INSPIRED by MD6's compression function as listed in the MIT paper: https://people.csail.mit.edu/rivest/pubs/RABCx08.pdf
                state[RING_BUF_INDEX(i)] ^= (state[RING_BUF_INDEX(i - 1)] ^ state[RING_BUF_INDEX(i - 2)]) ^ state[RING_BUF_INDEX(i - 3)];

                state[RING_BUF_INDEX(i)] ^= (state[RING_BUF_INDEX(i)] >> COMPRESSION_SHIFTS[(uint8_t)((cbyte) & 0xF % 5)]);
                // state[RING_BUF_INDEX(i)] ^= ((state[RING_BUF_INDEX(i)] >> COMPRESSION_SHIFTS[(uint8_t)((cbyte) & 0xF % 5)])) | (state[RING_BUF_INDEX(i)] << (8 - COMPRESSION_SHIFTS[(uint8_t)((cbyte) & 0xF % 5)]));
                                                                // Grab least significantt 4 bits from cbyte, then modulo 5 to index the shift array (no zero shifts!).
                                                                // XOR the current state byte with the shifted state byte to add more pseudo-randomness.
                lbyte = state[RING_BUF_INDEX(i)]; // Pushes back the first found collision by 10,000. But it is still at 3 characters. 4 characters is the next milestone!
            }
        }

        if(padded){
            delete[] paddedInput;
            paddedInput = nullptr;
        }

        memcpy(output, state, STATE_BUF_LEN);
    }
};