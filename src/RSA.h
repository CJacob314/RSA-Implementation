#ifndef __RSA_H
#define __RSA_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>

#include <string>
#include <sstream>


typedef boost::multiprecision::cpp_int BigInt;

#define EVEN(x) (!(x & 1))
#define ODD(x) (x & 1)

typedef BigInt RsaKey;

class RSA{
    private:
    RsaKey privateKey, publicKey;

    BigInt modExp(BigInt x, BigInt y, BigInt p);
    BigInt modInv(BigInt a, BigInt m);
    bool rabinMillerIsPrime(const BigInt& n, uint64_t accuracy);
    bool __rabinMillerHelper(BigInt d, BigInt n);
    BigInt generatePrime(uint16_t keyLength);

    std::string toAsciiStr(BigInt n);
    BigInt fromAsciiStr(const std::string& str);

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

    std::string encrypt(const char* message, uint64_t length);
    std::string encrypt(std::string message);
    std::string decrypt(std::string message);

    RsaKey getPrivateKey();
    RsaKey getPublicKey();

    void testPrimeDetection(BigInt n);
    void testLCG();
    void testPrimeGeneration(uint16_t keyLength);
};

#endif