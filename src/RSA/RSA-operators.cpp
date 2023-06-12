#include "../RSA.h"
#include "../Utilities.h"

bool RSA::operator!(){
    return isEmpty();
    // return (!publicKey && !privateKey);
}

RSA& RSA::operator=(const RSA& other){
    publicKey = other.publicKey;
    privateKey = other.privateKey;
    pubKeyBytes = other.pubKeyBytes;
    pubKeyBits = other.pubKeyBits;
    return *this;
}
