#include "../RSA.h"
#include "../Utilities.h"

BigInt stringToBigInt(const char* message, uint64_t length){
    BigInt messageInt = 0;
    for(uint64_t i = 0; i < length; i++){
        messageInt <<= 8;
        messageInt |= message[i];
    }

    return messageInt;
}

std::string bigIntToString(BigInt message){
    std::string messageString = "";
    while(message > 0){
        messageString = (char)(message & 0xFF) + messageString;
        message >>= 8;
    }

    return messageString;
}


// Only works given a and m are coprime, which they almost CERTAINLY are given my implementation.
// That is, unless I get VERY unlucky and my prime is a multiple of 65537.
// Runs in O(log(m)) and uses O(1) space.
BigInt RSA::modInv(BigInt a, BigInt m){
    BigInt m0 = m;
    BigInt y = 0, x = 1;
 
    if (m == 1)
        return 0;
 
    while (a > 1) {
        BigInt q = a / m;
        BigInt t = m;
 
        // Now run Extended Euclidean Algorithm
        m = a % m, a = t;
        t = y;
 
        y = x - q * y;
        x = t;
    }
 
    // We need to return a positive integer.
    if (x < 0)
        x += m0;
 
    return x;
}

BigInt RSA::modExp(BigInt x, BigInt y, BigInt p){
    BigInt z = 1;

    if(x >= p)
        x %= p;

    while(y > 0){
        if(ODD(y)){
            z = (z*x) % p;
        }

        y >>= 1; // Quick /= 2
        x = (x*x) % p;
    }

    return z;
}

bool RSA::rabinMillerIsPrime(const BigInt& n, uint64_t accuracy){
    if (n <= 1 || n == 4)  return false;
    if (n <= 3) return true;
    
    if(EVEN(n)) return false;

    BigInt d = n - 1;
    while (!(d % 2))
        d /= 2;
 
    for (uint64_t i = 0; i < accuracy; i++)
         if (!__rabinMillerHelper(d, n))
              return false;
 
    return true;
}

bool RSA::__rabinMillerHelper(BigInt d, BigInt n){
    BigInt a = 2 + lcg.next() % (n - 4);

    BigInt x = modExp(a, d, n);

    if(x == 1 || x == n - 1)
        return true;

    while (d != n - 1)
    {
        x = (x * x) % n;
        d *= 2;
 
        if (x == 1)      
            return false;
        if (x == n-1)    
            return true;
    }

    return false;
}

BigInt RSA::generatePrime(uint16_t keyLength){
    BigInt prime;

    while(!rabinMillerIsPrime(prime, 2)){
        BigInt min = BigInt(1) << (keyLength - 1);
        BigInt max = (BigInt(1) << keyLength) - 1;

        prime = lcg.next() % (max - min + 1) + min;
        
    }

    return prime;
}

RSA::BigLCG::BigLCG(){
    srand(time(NULL));
    this->seed = BigInt(rand());
}

BigInt RSA::BigLCG::next(){
    seed = (multiplier * seed + increment) % modulus;
    return seed;
}

RSA::RSA(uint16_t newKeyLength){
    BigInt p = generatePrime(newKeyLength / 2);
    BigInt q = generatePrime(newKeyLength / 2);
    publicKey = p * q;

    BigInt phi = (p - 1) * (q - 1);
    privateKey = modInv(e, phi);

    std::cout << "p: " << p << "\n\nq: " << q << "\n\nphi(p*q): " 
        << phi << "\n\nPublicKey(n=p*q): " << publicKey << "\n\nprivateKey: " << privateKey << "\n";
}

RSA::RSA(RsaKey privateKey, RsaKey publicKey){
    this->privateKey = privateKey;
    this->publicKey = publicKey;    
}

RSA::RSA(RsaKey publicKey){
    this->publicKey = publicKey;
}

void RSA::testLCG(){
    for(int i = 0; i < 10000; i++){
        std::cout << lcg.next() << "\n";
    }
}

void RSA::testPrimeDetection(BigInt n){
    if(this->rabinMillerIsPrime(n, 10)){
        std::cout << n << " is probably prime!" << "\n";
    } else {
        std::cout << n << " is not prime!" << "\n";
    }
}

void RSA::testPrimeGeneration(uint16_t keyLength){
    BigInt prime = this->generatePrime(keyLength);

    std::cout << prime << "\n";
}

std::string RSA::encrypt(const char* message, uint64_t length){
    if(!publicKey){
        throw std::runtime_error("No public key!");
        return 0;
    }

    BigInt messageInt = stringToBigInt(message, length);
    if(messageInt >= publicKey){
        // TODO: Finish this!
        // Chunk the message into encrypted chunks (with a separator, probably '-' since my ascii conversion functions do not ever generate that character)
        uint64_t pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
        uint64_t messageBits = boost::multiprecision::msb(messageInt) + 1;


    }

    
    BigInt encrypted = modExp(messageInt, e, publicKey);

    return toAsciiStr(encrypted);
}

std::string RSA::encrypt(std::string message){
    return encrypt(message.c_str(), message.length());
}

std::string RSA::decrypt(std::string message){
    if(!privateKey){
        throw std::runtime_error("No private key!");
        return "";
    }

    BigInt messageInt = fromAsciiStr(message);
    BigInt decrypted = modExp(messageInt, privateKey, publicKey);

    return bigIntToString(decrypted);
}

RsaKey RSA::getPrivateKey(){
    return privateKey;
}

RsaKey RSA::getPublicKey(){
    return publicKey;
}

std::string RSA::toAsciiStr(BigInt n){
    std::stringstream builder;

	for(char c = static_cast<char>(((uint8_t)n) & 0x0F) + 'A'; n; n >>= 4, c = static_cast<char>((((uint8_t)n) & 0x0F) + 'A')){
		builder << c;
	}

	return builder.str();
}

BigInt RSA::fromAsciiStr(const std::string& str){
    BigInt result = 0;
    uint64_t shift = 0;

    for (const char& c : str) {
        result |= (BigInt(c - 'A') << shift);
        shift += 4;
    }
	
    return result;
}