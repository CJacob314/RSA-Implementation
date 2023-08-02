#ifndef __RSA_H
#define __RSA_H

#define unary_function __unary_function

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>
#include <emscripten/bind.h>

#include <string>
#include <sstream>
#include <climits>
#include <optional>
#include <vector>

typedef boost::multiprecision::cpp_int BigInt;
using namespace emscripten;

typedef BigInt RsaKey;

class RSA{
    #define EVEN(x) (!(x & 1))
    #define ODD(x) (x & 1)
    #define OAEP_ENCODING_PARAM "D92PBJK2X9IPKVQ158O4ICUOFXK4Z5OG"
    #define JS_RAND_BYTES_STORE_CNT 65536 // Maximum amount of allowed by the WebCryptoAPI: https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
    #define HASH_BYTES 15 // My hashing algorithm outputs a fixed 15 bytes

    private:
    RsaKey privateKey, publicKey;
    uint16_t pubKeyBytes, pubKeyBits;
    std::vector<uint8_t> jsRandomBytes;
    std::string JsRandomScript;

    RSA() {}; // Empty constructor private only for use only in static builder-style "constructor" and in static RSA::emptyRSA() method (to be used for comparisons)

    BigInt modExp(BigInt, BigInt, BigInt);
    BigInt modInv(BigInt, BigInt);
    bool rabinMillerIsPrime(const BigInt&, uint64_t accuracy);
    bool __rabinMillerHelper(BigInt, BigInt);
    BigInt generatePrime(uint16_t keyLength);
    void populateRandomBytes();

    std::string toAsciiStr(BigInt);
    BigInt fromAsciiStr(const std::string&);

    std::string toAsciiCompressedStr(const BigInt&);
    std::string toAsciiCompressedStr(const uint8_t*, size_t);
    BigInt fromAsciiCompressedStr(const std::string&);
    
    const BigInt e = BigInt(1) << 16 | 0x1;

    class BigLCG{
        private:
        BigInt seed;

        const BigInt modulus = BigInt(1) << 128;
        const BigInt multiplier = BigInt(6364136223846793005) * 17;
        const BigInt increment = BigInt(1442695040888963407) * 23;

        public:
        BigLCG();
        BigInt next();
    };

    BigLCG lcg;

    public:

    static RSA& getInstance();
    static void genInstance(uint16_t keyLength);
    
    RSA(uint16_t newKeyLength);
    RSA(RsaKey privateKey, RsaKey publicKey);
    RSA(RsaKey publicKey);
    static std::optional<RSA> buildFromKeyFile(const char* filepath, bool importPrivateKey = false);
    static RSA buildFromString(const std::string& s, bool importPrivateKey = false);
    static RSA empty(); // Only for use in comparisons, will not encrypt or decrypt anything [unless you manually call importFromFile(), in which case the ! operator will no longer return true].

    // ! operator will return true if and only if the RSA object is invalid/empty
    bool operator!();
    RSA& operator=(const RSA& other);

    bool isEmpty();
    bool hasPrivate();

    std::string encrypt(const std::string& message, bool compressedAsciiOutput = false);
    std::string decrypt(const std::string& message, bool compressedAsciiInput = false);
    std::string sign(const std::string& message);
    bool verify(const std::string& signedMessage);
    std::string getFingerprint();

    bool exportToFile(const char* filepath, bool exportPrivateKey = false);
    std::string exportToString(bool exportPrivateKey);
    bool importFromFile(const char* filepath, bool importPrivateKey = false);
    bool importFromString(const std::string& s, bool importPrivateKey = false);

    std::string getPrivateKey() const;
    std::string getPublicKey() const;
    uint16_t getPublicKeyLength() const;

    #ifdef DEBUG_TESTING
        void testPrimeDetection(BigInt n);
        void testLCG();
        void testPrimeGeneration(uint16_t keyLength);
    #endif
};

#endif