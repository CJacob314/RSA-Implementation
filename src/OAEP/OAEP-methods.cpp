#include "../OAEP.h"
#include "../hashing.h"

namespace OAEP {
    // Implemented from steps here: https://datatracker.ietf.org/doc/html/rfc2437#section-10.2.1
    std::string MGF1(std::string seed, uint16_t maskLength){
        if(maskLength > 0x100000000UL){
            throw std::runtime_error("OAEP::MGF1() maskLength too large");
        }

        std::string T = "";

        // Make sure the copied-by-value string `seed` has a high enough underlying capacity
        if(seed.capacity() < seed.size() + 4 + 1){ // Integer constant expressions evaluated at compile-time even with -O0
            seed.reserve(seed.size() + 4 + 1);
        }

        // Loop for 0 to ceil(maskLength / HASH_BYTES) - 1 [upper bound not inclusive]
        // for(uint32_t i = 0; i < static_cast<uint32_t>(1 + ((maskLength - 1) / HASH_BYTES) - 1); i++){
        for(uint32_t i = 0; i < static_cast<uint32_t>((maskLength + HASH_BYTES - 1) / HASH_BYTES); i++){
            char hashBuf[HASH_BYTES];
            std::string i_str(reinterpret_cast<char*>(&i), 4);
            seed += i_str;

            // Create hash of (seed || C) [concatenation || from the RFC docs]
            Hashing::hash(hashBuf, seed.c_str(), seed.length());
            
            // Append to T
            T += std::string(hashBuf, HASH_BYTES);
        }


        // Return the first maskLength bytes of T
        return T.substr(0, maskLength);
    }

    // Implemented from steps here: https://datatracker.ietf.org/doc/html/rfc2437#section-9.1.1.1
    std::string pad(std::string message, uint32_t pLen, const char* P, uint32_t emLen){

        uint32_t mLen = message.size();

        // Verify that ||M|| <= emLen-2hLen-1
        if(mLen > static_cast<int64_t>(emLen) - (2LL * HASH_BYTES) - 1LL){
            std::cerr << "OAEP::pad() message too long\n";
            throw std::runtime_error("OAEP::pad() message too long");
        }

        // Generate octet string PS consisting of emLen - ||M|| - 2hLen - 1 zero octets.
        std::string PS = std::string(emLen - mLen - (2 * HASH_BYTES) - 1, 0x00);

        // Make pHash
        char pHash[HASH_BYTES];
        Hashing::hash(pHash, P, pLen);

        // Make DB: DB = pHash || PS || 01 || M
        std::string DB = std::string(pHash, HASH_BYTES) + PS + "\x01" + message;

        // Generate the random octet string seed of length HASH_BYTES
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 0xFF);
        std::string seed = "";
        for(uint32_t i = 0; i < HASH_BYTES; i++){
            seed += static_cast<char>(dis(gen));
        }

        // Make dbMask
        std::string dbMask = MGF1(seed, emLen - HASH_BYTES);

        // XOR DB and dbMask
        for(uint32_t i = 0; i < emLen - HASH_BYTES; i++){
            DB[i] ^= dbMask[i];
        }

        // Make seedMask
        std::string seedMask = MGF1(DB, HASH_BYTES);

        // XOR seed and seedMask
        for(uint32_t i = 0; i < HASH_BYTES; i++){
            seed[i] ^= seedMask[i];
        }

        // Return EM = 0x0000 + maskedSeed || maskedDB
        return seed + DB;
    }

    std::string unpad(std::string padded, uint32_t pLen, const char* P){
        uint64_t emLen = padded.size();
        if(emLen < 2 * HASH_BYTES + 1){
            std::cerr << "OAEP::unpad() decoding error\n";
            throw std::runtime_error("OAEP::unpad() decoding error");
        }

        // Make maskedSeed and maskedDB
        std::string maskedSeed = padded.substr(0, HASH_BYTES);
        std::string maskedDB = padded.substr(HASH_BYTES);


        // Make seedMask
        std::string seedMask = MGF1(maskedDB, HASH_BYTES);

        // Make seed
        std::string seed = maskedSeed;
        for(uint32_t i = 0; i < HASH_BYTES; i++){
            seed[i] ^= seedMask[i];
        }

        // Make dbMask
        std::string dbMask = MGF1(seed, emLen - HASH_BYTES);

        // Make DB = maskedDB \xor dbMask
        std::string DB = maskedDB;
        for(uint32_t i = 0; i < emLen - HASH_BYTES; i++){
            DB[i] ^= dbMask[i];
        }

        // Make pHash
        char pHashCStr[HASH_BYTES];
        Hashing::hash(pHashCStr, P, pLen);
        std::string pHash = std::string(pHashCStr, HASH_BYTES);

        // Separate DB into pHash' consisting of the first hLen octets of DB and the (empty okay) string PS with all zero octets following pHash'
        std::string pHashPrime = DB.substr(0, HASH_BYTES);
        std::string PS = DB.substr(HASH_BYTES);
        std::string::size_type mStart = PS.find_first_of(static_cast<char>(0x01));
        if(mStart == std::string::npos){
            std::cerr << "OAEP::unpad() decoding error\n";
            throw std::runtime_error("OAEP::unpad() decoding error");
        }
        std::string M = PS.substr(mStart + 1);

        // Verify that pHash = pHash'
        if(pHash != pHashPrime){
            std::cerr << "OAEP::unpad() decoding error\n";
            throw std::runtime_error("OAEP::unpad() decoding error");
        }

        // Final return
        return M;
    }

};