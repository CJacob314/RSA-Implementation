#ifndef __RSA_H
#define __RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>

#include <string>
#include <sstream>
#include <climits>
#include <optional>
#include <sys/random.h> // For cryptographically secure random numbers

typedef boost::multiprecision::cpp_int BigInt;

typedef BigInt RsaKey;

class RSA{
    #define EVEN(x) (!(x & 1))
    #define ODD(x) (x & 1)
    #define OAEP_ENCODING_PARAM "D92PBJK2X9IPKVQ158O4ICUOFXK4Z5OG"

    private:
    RsaKey privateKey, publicKey;
    uint16_t pubKeyBytes, pubKeyBits;

    RSA() {}; // Empty constructor private only for use only in static builder-style "constructor" and in static RSA::emptyRSA() method (to be used for comparisons)

    BigInt modExp(BigInt x, BigInt y, BigInt p);
    BigInt modInv(BigInt a, BigInt m);
    bool rabinMillerIsPrime(const BigInt& n, uint64_t accuracy);
    bool __rabinMillerHelper(BigInt d, BigInt n);
    BigInt generatePrime(uint16_t keyLength);

    std::string toAsciiStr(BigInt n);
    BigInt fromAsciiStr(const std::string& str);

    std::string toAsciiCompressedStr(const BigInt& n);
    std::string toAsciiCompressedStr(const uint8_t*, size_t);
    BigInt fromAsciiCompressedStr(const std::string& ascii);
    
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
    
    RSA(uint16_t newKeyLength);
    RSA(RsaKey privateKey, RsaKey publicKey);
    RSA(RsaKey publicKey);
    static std::optional<RSA> buildFromKeyFile(const char* filepath, bool importPrivateKey = false);
    static RSA empty(); // Only for use in comparisons, will not encrypt or decrypt anything [unless you manually call importFromFile(), in which case the ! operator will no longer return true].

    // ! operator will return true if and only if the RSA object is invalid/empty
    bool operator!();

    std::string encrypt(const char* message, uint64_t length, bool compressedAsciiOutput = false);
    std::string encrypt(const std::string& message, bool compressedAsciiOutput = false);
    std::string decrypt(const std::string& message, bool compressedAsciiInput = false);
    std::string sign(const std::string& message);
    bool verify(const std::string& signedMessage);
    std::string getFingerprint();

    bool exportToFile(const char* filepath, bool exportPrivateKey = false, bool forWebVersion = false);
    bool importFromFile(const char* filepath, bool importPrivateKey = false);

    RsaKey getPrivateKey();
    RsaKey getPublicKey();
    uint64_t getPublicKeyLength();

    #ifdef DEBUG_TESTING
        void testPrimeDetection(BigInt n);
        void testLCG();
        void testPrimeGeneration(uint16_t keyLength);
    #endif
};

#endif