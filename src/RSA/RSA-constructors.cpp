#include "../RSA.h"
#include "../Utilities.h"

RSA::RSA(uint16_t newKeyLength){
    // Just use std::string and the + operator to create the JsRandomScript string
    // TODO: Write a constexpr function to do this with char buffers at COMPILE time!
    JsRandomScript = "let r = new Uint8Array(" + std::to_string(JS_RAND_BYTES_STORE_CNT) + "); let s = ''; crypto.getRandomValues(r); r.forEach((i) => {s += String.fromCharCode(i);}); s";

    // Reserve space for the SECURE random bytes crypto.getRandomValues() generates.
    jsRandomBytes.reserve(JS_RAND_BYTES_STORE_CNT);

    if(newKeyLength < 1024){
        throw std::runtime_error("Key length must be at least 1024 bits!");
        return;
    }

    BigInt p = generatePrime(newKeyLength >> 1);
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
