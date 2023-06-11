#include "../RSA.h"
#include "../Utilities.h"

RSA::RSA(uint16_t newKeyLength){
    if(newKeyLength < 1024){
        throw std::runtime_error("Key length must be at least 1024 bits!");
        return;
    }

    BigInt p = generatePrime((newKeyLength >> 1) + (ODD(newKeyLength) ? 1 : 0)); // This only slightly raises the probability of hitting the correct bit-length on the nose. It will always be within 1, though.
    BigInt q = generatePrime(newKeyLength >> 1);
    publicKey = p * q;

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = (pubKeyBits < 8) ? 1 : pubKeyBits >> 3;

    BigInt phi = (p - 1) * (q - 1);
    privateKey = modInv(e, phi);

    #ifdef DEBUG_TESTING
        std::cout << "p: " << p << "\n\nq: " << q << "\n\nphi(p*q): " 
            << phi << "\n\nPublicKey(n=p*q): " << publicKey << "\n\nprivateKey: " << privateKey << "\n";
    #endif
}

RSA::RSA(RsaKey privateKey, RsaKey publicKey){
    this->privateKey = privateKey;
    this->publicKey = publicKey;

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = pubKeyBits >> 3;
}

RSA::RSA(RsaKey publicKey){
    this->publicKey = publicKey;

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = pubKeyBits >> 3;
}

std::optional<RSA> RSA::buildFromKeyFile(const char* filepath, bool importPrivateKey){
    RSA rsa;

    try {    
        if(rsa.importFromFile(filepath, importPrivateKey)){
            return std::make_optional(rsa);
        } else {
            return std::nullopt;
        }
    } catch (std::runtime_error& e){
        return {};
    }
}