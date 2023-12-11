#include "../OAEP.h"
#include "../hashing.h"

namespace OAEP {
// Implemented from steps here: https://datatracker.ietf.org/doc/html/rfc2437#section-10.2.1
// ! Intentional copy by value for std::string seed !
std::string MGF1(std::string seed, uint16_t maskLength) {
    if (maskLength > 0xF00000000UL) {
        throw std::runtime_error("OAEP::MGF1() maskLength too large");
    }

    std::string T = "";

    // Make sure the copied-by-value string `seed` has a high enough underlying capacity
    if (seed.capacity() < seed.size() + 4 + 1) { // Integer constant expressions evaluated at compile-time even with -O0
        seed.reserve(seed.size() + 4 + 1);
    }

    // Loop for 0 to ceil(maskLength / HASH_BYTES) - 1 [upper bound not inclusive]
    // for(uint32_t i = 0; i < static_cast<uint32_t>(1 + ((maskLength - 1) / HASH_BYTES) - 1); i++){
    for (uint32_t i = 0; i < static_cast<uint32_t>((maskLength + HASH_BYTES - 1) / HASH_BYTES); i++) {
        char hashBuf[HASH_BYTES];
        uint32_t i_be = htonl(i); // To ensure big endian on every system (TCP network order is defined as big endian everywhere)
        std::string C(reinterpret_cast<char*>(&i_be), 4);

        // Create hash of (seed || C) [concatenation || from the RFC docs]
        std::string tmp = seed + C;
        Hashing::hash(hashBuf, tmp.c_str(), tmp.length());

        // Append to T
        T += std::string(hashBuf, HASH_BYTES);
    }

    // Return the first maskLength bytes of T
    return T.substr(0, maskLength);
}

// Implementation from this RFC doc: https://datatracker.ietf.org/doc/html/rfc8017
std::string pad(const std::string& message, uint32_t k) {
    // Initialize variables
    static constexpr uint32_t hLen = HASH_BYTES;
    static bool firstCall = true;
    uint32_t mLen = message.size();

    // If this is the first run, initialize lHash
    static char lHash_Buf[HASH_BYTES];
    static std::string lHash;
    if (firstCall) {
        Hashing::hash(lHash_Buf, "", 0);
        lHash = std::string(lHash_Buf, HASH_BYTES);
        firstCall = false;
    }

    // Verify that mLen <= k - 2hLen - 2
    if (mLen > static_cast<int64_t>(k) - (2LL * hLen) - 2LL) {
        std::cerr << "OAEP::pad() message too long\n";
        throw std::runtime_error("OAEP::pad() message too long");
    }

    // Generate octet string PS consisting of k - mLen - 2hLen - 2 zero octets.
    std::string PS = std::string(k - mLen - (2 * HASH_BYTES) - 2, 0x00);

    // Make DB: DB = lHash || PS || 0x01 || M.
    std::string DB = lHash + PS + "\x01" + message;

    // Generate the random octet string seed of length HASH_BYTES
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 0xFF);
    std::string seed(hLen, 0);
    for (char& c : seed) {
        c = static_cast<char>(dis(gen));
    }

    // Let dbMask = MGF(seed, k - hLen - 1)
    std::string dbMask = MGF1(seed, k - hLen - 1);

    // Let maskedDB = DB \xor dbMask
    std::string maskedDB = DB;
    for (uint32_t i = 0; i < dbMask.size(); i++) {
        maskedDB[i] ^= dbMask[i];
    }

    // Let seedMask = MGF(maskedDB, hLen).
    std::string seedMask = MGF1(maskedDB, hLen);

    // Let maskedSeed = seed \xor seedMask.
    std::string maskedSeed = seed;
    for (uint32_t i = 0; i < seedMask.size(); i++) {
        maskedSeed[i] ^= seedMask[i];
    }

    // Return EM := 0xFF || maskedSeed || maskedDB
    /*
    This is a slight modification to the original procedure documented in the RFC document. Prepending a 0x00 byte
    causes issues when the string is converted to a BigInt, because this is a leading zero and is thus dropped!
    */

    std::string EM(1 + maskedSeed.size() + maskedDB.size(), 0xFF);
    std::copy(maskedSeed.begin(), maskedSeed.end(), EM.begin() + 1);
    std::copy(maskedDB.begin(), maskedDB.end(), EM.begin() + 1 + maskedSeed.size());
    return EM;
}

// Implementation from this RFC doc: https://datatracker.ietf.org/doc/html/rfc8017
std::string unpad(const std::string& EM, uint32_t k) {
    static constexpr uint32_t hLen = HASH_BYTES;
    static bool firstCall = true;

    // If this is the first run, initialize lHash
    /* TODO: Make lHash a static class variable, initialized to a defualt value (or maybe a unique_ptr with a unique value), then
       set it only ONCE, EVER. Right now, through multiple RSA objects, it is set a total of twice, once with the first pad() call
       and once with the first unpad() call.
    */
    static char lHash_Buf[HASH_BYTES];
    static std::string lHash;
    static std::mutex mtx; // So that no two threads attempt initialization at the same time.
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (firstCall) {
            Hashing::hash(lHash_Buf, "", 0);
            lHash = std::string(lHash_Buf, HASH_BYTES);
            firstCall = false;
        }
    }

    /* Extract the components of <encoded message> = Y || maskedSeed || maskedDB, where Y is a single zero octet,
    maskedSeed is a string of hLen octets, and maskedDB is a string of length k - hLen - 1 octets */
    std::string Y = EM.substr(0, 1);
    std::string maskedSeed = EM.substr(1, hLen);
    std::string maskedDB = EM.substr(1 + hLen, k - hLen - 1);

    // Let seedMask = MGF(maskedDB, hLen).
    std::string seedMask = MGF1(maskedDB, hLen);

    // Let seed = maskedSeed \xor seedMask.
    std::string seed = maskedSeed;
    for (size_t i = 0; i < seed.size(); i++) {
        seed[i] ^= seedMask[i];
    }

    // Let dbMask = MGF(seed, k - hLen - 1).
    std::string dbMask = MGF1(seed, k - hLen - 1);

    // Let DB = maskedDB \xor dbMask.
    std::string DB = maskedDB;
    for (uint32_t i = 0; i < dbMask.size(); i++) {
        DB[i] ^= dbMask[i];
    }

    /* Separate DB into lHash' || PS || 0x01 || M, where lHash' (lHash_P) is a string of length hLen,
    PS is a possibly empty padding string consisting only of 0x00 octets (not needed for my use),
    and M is the message to be recovered. */
    std::string lHash_P = DB.substr(0, hLen);
    size_t M_start = DB.find('\x01', hLen) + 1;
    if (M_start == std::string::npos) {
        std::cerr << "OAEP::unpad(): Decoding error!\n";
        throw std::runtime_error("OAEP::unpad(): Decoding error!");
    }

    return DB.substr(M_start);
}

}; // namespace OAEP