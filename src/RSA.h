#ifndef __RSA_H
#define __RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/integer/mod_inverse.hpp>

#include <climits>
#include <optional>
#include <sstream>
#include <string>
#include <atomic>       // For multithreading
#include <future>       // For multithreading
#include <mutex>        // For multithreading
#include <thread>       // For multithreading
#include <sys/random.h> // For cryptographically secure random numbers

#include "StringAssembler.h"

typedef boost::multiprecision::cpp_int BigInt;
typedef BigInt RsaKey;

class RSA {
#define EVEN(x) (!(x & 1))
#define ODD(x) (x & 1)
#define OAEP_ENCODING_PARAM "D92PBJK2X9IPKVQ158O4ICUOFXK4Z5OG"

    private:
    const unsigned int Num_Prime_Search_Threads = std::thread::hardware_concurrency();
    std::array<BigInt, 2> primes;        // The threads will write to this array when they've found a sufficient prime.
    std::mutex mtx;                      // To guard threaded access to the above `primes` array.
    std::atomic<uint8_t> primesFound{0}; // The control which index of `primes` to write to once a prime has been found.
    std::atomic<bool> stopFlag{false};   // To signal the threads to stop searching for primes.
    std::condition_variable cv;          // To signal the main thread when we've found two large primes.

    RsaKey privateKey, publicKey; // `publicKey` here is JUST the RSA modulus, since I always use e = 2^16 - 1.
    uint16_t pubKeyBytes, pubKeyBits;

    RSA(){}; // Empty constructor private only for use only in static builder-style "constructor" and in static RSA::emptyRSA() method (to
             // be used for comparisons)

    bool rabinMillerIsPrime(const BigInt& n, uint64_t accuracy);
    bool __rabinMillerHelper(BigInt d, BigInt n);
    void generatePrime(uint16_t keyLength);

    std::string toAsciiStr(BigInt n);
    BigInt fromAsciiStr(const std::string& str);

    std::string toAsciiCompressedStr(const BigInt& n);
    std::string toAsciiCompressedStr(const uint8_t*, size_t);
    BigInt fromAsciiCompressedStr(const std::string& ascii);

    const BigInt e = BigInt(1) << 16 | 0x1;

    class BigLCG {
        private:
        BigInt seed;

        const BigInt modulus = BigInt(1) << 128;
        const BigInt multiplier = BigInt(6364136223846793005) * 17;
        const BigInt increment = BigInt(1442695040888963407) * 23;

        public:
        BigLCG();
        BigInt next();
    };

    public:
    RSA(uint16_t newKeyLength);
    RSA(RsaKey privateKey, RsaKey publicKey);
    RSA(RsaKey publicKey);
    RSA(RSA&& other) noexcept; // Move constructor
    static std::optional<RSA> buildFromKeyFile(const char* filepath, bool importPrivateKey = false);
    static RSA empty(); // Only for use in comparisons, will not encrypt or decrypt anything [unless you manually call importFromFile(), in
                        // which case the ! operator will no longer return true].

    // ! operator will return true if and only if the RSA object is invalid/empty
    bool operator!();

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
#endif
};

#endif