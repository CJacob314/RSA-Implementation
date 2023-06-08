#include "../RSA.h"
#include "../OAEP.h"
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

std::string RSA::toAsciiCompressedStr(const BigInt& n){
    std::vector<unsigned char> rawVec;
    export_bits(n, std::back_inserter(rawVec), 8);
    std::string raw(rawVec.begin(), rawVec.end());
    size_t rawLen = rawVec.size();

    std::string ascii;
    static const char tbl[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    rawLen = !rawLen ? raw.size() : rawLen;
    uint16_t buffer = 0;
    int bufferBits = 0;
    
    for(size_t i = 0; i < rawLen; ++i) {
        uint8_t rawByte = static_cast<uint8_t>(raw[i]);
        buffer = (buffer << CHAR_BIT) | rawByte;
        bufferBits += CHAR_BIT;

        while (bufferBits >= 6) {
            bufferBits -= 6;
            uint8_t cbyte = static_cast<uint8_t>(buffer >> bufferBits);
            ascii += tbl[cbyte];
            buffer &= (1 << bufferBits) - 1;
        }
    }

    // if there are remaining bits, append them as well
    if (bufferBits > 0) {
        buffer <<= (6 - bufferBits);
        ascii += tbl[buffer];
    }

    return ascii;
}

BigInt RSA::fromAsciiCompressedStr(const std::string& ascii){
    std::string raw;
    size_t asciiLen = ascii.size();
    uint16_t buffer = 0;
    int bufferBits = 0;
    
    for(size_t i = 0; i < asciiLen; ++i) {
        char asciiChar = ascii[i];
        uint8_t cbyte;
        if ('0' <= asciiChar && asciiChar <= '9') cbyte = asciiChar - '0';
        else if ('A' <= asciiChar && asciiChar <= 'Z') cbyte = asciiChar - 'A' + 10;
        else if ('a' <= asciiChar && asciiChar <= 'z') cbyte = asciiChar - 'a' + 36;
        else if (asciiChar == '+') cbyte = 62;
        else /* asciiChar == '/' */ cbyte = 63;

        buffer = (buffer << 6) | cbyte;
        bufferBits += 6;

        while (bufferBits >= CHAR_BIT) {
            bufferBits -= CHAR_BIT;
            uint8_t rawByte = static_cast<uint8_t>(buffer >> bufferBits);
            raw += rawByte;
            buffer &= (1 << bufferBits) - 1;
        }
    }

    BigInt result = 0;
    std::vector<unsigned char> rawVec(raw.begin(), raw.end());
    import_bits(result, rawVec.begin(), rawVec.end());
    return result;
}

std::string RSA::encrypt(const char* message, uint64_t length, bool compressedAsciiOutput){
    static const char* P = OAEP_ENCODING_PARAM;
    static const uint32_t pLen = 32;
    static const uint32_t maxMsgLen = (pubKeyBytes - 1) - (2 * HASH_BYTES) - 1;

    if(!publicKey){
        throw std::runtime_error("No public key!");
        return 0;
    }

    if(length > maxMsgLen){ // Chunking needed for OAEP::pad to work!
        uint64_t chunkSize = maxMsgLen - 2;
        uint64_t strChunkCharCnt = (chunkSize < 8) ? 1 : chunkSize >> 3;
        uint64_t strChunkCnt = length / strChunkCharCnt + 1;

        std::string encStr = "";
        for(uint64_t i = 0; i < strChunkCnt; i++){
            std::string toPad = std::string(message + (i * strChunkCharCnt)).substr(0, std::min(strChunkCharCnt, length - (i * strChunkCharCnt)));
            std::string padded = OAEP::pad(toPad, pLen, P, pubKeyBytes - 1);
            std::vector<unsigned char> paddedVec(padded.begin(), padded.end());
            BigInt converted;
            import_bits(converted, paddedVec.begin(), paddedVec.end());

            // Truncate padded to std::min(strChunkCharCnt, length - (i * strChunkCharCnt)) length
            padded = padded.substr(0, std::min(strChunkCharCnt, length - (i * strChunkCharCnt)));
            BigInt chunkEncrypted = modExp(converted, e, publicKey);
            if(compressedAsciiOutput){
                encStr += toAsciiCompressedStr(chunkEncrypted) + "|";
            } else
                encStr += toAsciiStr(chunkEncrypted) + "|";
        }

        return encStr;
    }
    
    std::string padded = OAEP::pad(message, pLen, P, pubKeyBytes - 1);
    std::vector<unsigned char> paddedVec(padded.begin(), padded.end());
    BigInt converted;
    import_bits(converted, paddedVec.begin(), paddedVec.end());

    BigInt encrypted = modExp(converted, e, publicKey);
    if(compressedAsciiOutput){
        return toAsciiCompressedStr(encrypted);
    }
    else
        return toAsciiStr(encrypted);
}

std::string RSA::encrypt(std::string message, bool compressedAsciiOutput){
    return encrypt(message.c_str(), message.length(), compressedAsciiOutput);
}

std::string RSA::decrypt(std::string message, bool compressedAsciiInput){
    if(!privateKey){
        throw std::runtime_error("No private key!");
        return "";
    }

    std::string decrypted = "";
    std::string chunk = "";

    // Assemble and decrypt the chunks
    for(const char& c : message){
        if(c == '|'){
            BigInt chunkInt;
            if(compressedAsciiInput){
                chunkInt = fromAsciiCompressedStr(chunk);
            } else
                BigInt chunkInt = fromAsciiStr(chunk);
            
            BigInt decryptedChunk = modExp(chunkInt, privateKey, publicKey);
            // decrypted += bigIntToString(decryptedChunk); // Append decrypted chunk

            std::vector<unsigned char> beforeUnpadVec;
            export_bits(decryptedChunk, std::back_inserter(beforeUnpadVec), 8);
            std::string beforeUnpad(beforeUnpadVec.begin(), beforeUnpadVec.end());
            decrypted += OAEP::unpad(beforeUnpad, 32, OAEP_ENCODING_PARAM);
            chunk = "";
        } else {
            chunk += c;
        }
    }

    // In case string does not terminate with '|'
    if (!chunk.empty()) {
        BigInt chunkInt;
        if(compressedAsciiInput){
            chunkInt = fromAsciiCompressedStr(chunk);
        } else
            chunkInt = fromAsciiStr(chunk);

        BigInt decryptedChunk = modExp(chunkInt, privateKey, publicKey);
        
        std::vector<unsigned char> beforeUnpadVec;
        export_bits(decryptedChunk, std::back_inserter(beforeUnpadVec), 8);
        std::string beforeUnpad(beforeUnpadVec.begin(), beforeUnpadVec.end());
        
        decrypted += OAEP::unpad(beforeUnpad, 32, OAEP_ENCODING_PARAM);
    }

    return decrypted;
}

RsaKey RSA::getPrivateKey(){
    return privateKey;
}

RsaKey RSA::getPublicKey(){
    return publicKey;
}

std::string RSA::toAsciiStr(BigInt n){
    std::stringstream builder;

    // n > 0 because -1 >> anything == -1
	for(unsigned char c = static_cast<unsigned char>((uint8_t)(n & 0x0F)) + 'J'; n > 0; n >>= 4, c = static_cast<unsigned char>(((uint8_t)(n & 0x0F)) + 'J')){
		builder << c;
	}

	return builder.str();
}

BigInt RSA::fromAsciiStr(const std::string& str){
    BigInt result = 0;
    uint64_t shift = 0;

    for (const char& c : str) {
        result |= (BigInt(c - 'J') << shift);
        shift += 4;
    }
	
    return result;
}

uint64_t RSA::getPublicKeyLength(){
    return boost::multiprecision::msb(publicKey) + 1;
}

#ifdef DEBUG_TESTING
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
#endif