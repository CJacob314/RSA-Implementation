#include "../OAEP.h"
#include "../RSA.h"
#include "../Utilities.h"
#include "../hashing.h"

BigInt stringToBigInt(const char* message, uint64_t length) {
    BigInt messageInt = 0;
    for (uint64_t i = 0; i < length; i++) {
        messageInt <<= 8;
        messageInt |= message[i];
    }

    return messageInt;
}

std::string bigIntToString(BigInt message) {
    std::string messageString = "";
    while (message > 0) {
        messageString = (char)(message & 0xFF) + messageString;
        message >>= 8;
    }

    return messageString;
}

inline bool RSA::rabinMillerIsPrime(const BigInt& n, uint64_t accuracy) {
    return boost::multiprecision::miller_rabin_test(n, accuracy, rng);
}

bool RSA::__rabinMillerHelper(BigInt d, BigInt n) {
    thread_local BigLCG lcg;

    BigInt a = 2 + lcg.next() % (n - 4);

    BigInt x = boost::multiprecision::powm(a, d, n);

    if (x == 1 || x == n - 1) return true;

    while (d != n - 1) {
        x = (x * x) % n;
        d *= 2;

        if (x == 1) return false;
        if (x == n - 1) return true;
    }

    return false;
}

void RSA::populateRandomBytes() {
    std::string r(emscripten_run_script_string(JsRandomScript.c_str()));
    jsRandomBytes.assign(r.begin(), r.end());
}

void RSA::generatePrime(uint16_t keyLength) {
    static size_t randomBytesIdx = 0;
    BigInt prime;
    bool foundPrime = false;

    while (!stopFlag.load() && !(foundPrime = rabinMillerIsPrime(prime, 2))) {
        unsigned long bytes = (keyLength + 7) / 8; // Calculate needed number of bytes to store keyLength bits.
        unsigned long remBits = keyLength % 8;     // Number of bits that will be used in the last byte (so I can AND out the extra bits)

        std::vector<uint8_t> v(
            bytes); // Reserve room in vector to store our random bytes at the same time as initializing all uint8_t's to 0.

        if (randomBytesIdx + bytes > jsRandomBytes.size()) {
            populateRandomBytes();
            randomBytesIdx = 0;
        }

        memcpy(v.data(), jsRandomBytes.data() + randomBytesIdx, bytes);
        randomBytesIdx += bytes;

        // Clear uneeded bits of the last byte
        if (remBits) {
            v[0] &= static_cast<uint8_t>((1 << remBits) - 1);
        }

        // Import to prime
        import_bits(prime, v.begin(), v.end());

        // Essentially OR in a 1 to the MSB to make sure that the number is as big as requested by the user.
        bit_set(prime, keyLength - 1);

        // Also OR in a 1 to the LSB, because no even natural number is prime besides 2
        bit_set(prime, 0);
    }

    if (!foundPrime) {
        // We were told to stop, so return.
        return;
    } else {
        // Prime number (probably) found!
        std::unique_lock<std::mutex> lock(mtx); // Lock the mutex
        if (primesFound.load() >= 2) {
            // If the primeIdx is >= 2 BEFORE we increment it, PREVENT RACE CONDITION!
            return;
        }

        uint8_t primeIdx = primesFound.fetch_add(1);

        primes[primeIdx] = prime;

        if (primesFound >= 2) {
            stopFlag.store(true); // Tell other threads to stop.
            cv.notify_one();      // Notify main thread we have found two primes.
        }
    }
}

RSA::BigLCG::BigLCG() {
    srand(time(NULL));
    this->seed = BigInt(rand());
}

BigInt RSA::BigLCG::next() {
    seed = (multiplier * seed + increment) % modulus;
    return seed;
}

std::string RSA::toAsciiCompressedStr(const uint8_t* data, size_t len) {
    std::string ascii;
    static const char tbl[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

    uint16_t buffer = 0;
    int bufferBits = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t rawByte = data[i];
        buffer = (buffer << CHAR_BIT) | rawByte;
        bufferBits += CHAR_BIT;

        while (bufferBits >= 6) {
            bufferBits -= 6;
            uint8_t cbyte = static_cast<uint8_t>(buffer >> bufferBits);
            ascii += tbl[cbyte];
            buffer &= (1 << bufferBits) - 1;
        }
    }

    if (bufferBits > 0) {
        buffer <<= (6 - bufferBits);
        ascii += tbl[buffer];
    }

    return ascii;
}

std::string RSA::toAsciiCompressedStr(const BigInt& n) {
    std::vector<unsigned char> rawVec;
    export_bits(n, std::back_inserter(rawVec), 8);
    std::string raw(rawVec.begin(), rawVec.end());
    size_t rawLen = rawVec.size();

    std::string ascii;
    static const char tbl[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    rawLen = !rawLen ? raw.size() : rawLen;
    uint16_t buffer = 0;
    int bufferBits = 0;

    for (size_t i = 0; i < rawLen; ++i) {
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

BigInt RSA::fromAsciiCompressedStr(const std::string& ascii) {
    std::string raw;
    size_t asciiLen = ascii.size();
    uint16_t buffer = 0;
    int bufferBits = 0;

    for (size_t i = 0; i < asciiLen; ++i) {
        char asciiChar = ascii[i];
        uint8_t cbyte;
        if ('0' <= asciiChar && asciiChar <= '9')
            cbyte = asciiChar - '0';
        else if ('A' <= asciiChar && asciiChar <= 'Z')
            cbyte = asciiChar - 'A' + 10;
        else if ('a' <= asciiChar && asciiChar <= 'z')
            cbyte = asciiChar - 'a' + 36;
        else if (asciiChar == '+')
            cbyte = 62;
        else /* asciiChar == '/' */
            cbyte = 63;

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

std::string RSA::encrypt(const std::string& msg, bool compressedAsciiOutput) {
    static const char* P = OAEP_ENCODING_PARAM;
    static const uint32_t pLen = 32;
    const uint32_t maxMsgLen = (pubKeyBytes - 1) - (2 * HASH_BYTES) - 3;

    const char* message = msg.c_str();
    uint64_t length = msg.size();

    if (!publicKey) {
        throw std::runtime_error("No public key!");
        return 0;
    }

    if (length > maxMsgLen) { // Chunking needed for OAEP::pad to work!
        uint64_t strChunkCharCnt = maxMsgLen;
        uint64_t strChunkCnt = length / strChunkCharCnt;
        if (length % strChunkCharCnt) {
            strChunkCnt++;
        }

        std::string encStr = "";
        for (uint64_t i = 0; i < strChunkCnt; i++) {
            std::string toPad = std::string(message + (i * strChunkCharCnt), std::min(strChunkCharCnt, length - (i * strChunkCharCnt)));

            std::string padded;
            try {
                padded = OAEP::pad(toPad, pubKeyBytes - 1);
            } catch (std::runtime_error& e) {
                throw e;
                return "";
            }

            std::vector<unsigned char> paddedVec(padded.begin(), padded.end());
            BigInt converted;
            import_bits(converted, paddedVec.begin(), paddedVec.end());

            // Truncate padded to std::min(strChunkCharCnt, length - (i * strChunkCharCnt)) length
            // padded = padded.substr(0, std::min(strChunkCharCnt, length - (i * strChunkCharCnt)));
            BigInt chunkEncrypted = boost::multiprecision::powm(converted, e, publicKey);

            if (compressedAsciiOutput) {
                encStr += toAsciiCompressedStr(chunkEncrypted) + "|";
            } else {
                encStr += toAsciiStr(chunkEncrypted) + "|";
            }
        }

        return encStr;
    }
    std::string padded;
    std::cout << "Calling OAEP::pad with message length: " << length << "\n";
    try {
        padded = OAEP::pad(std::string(message, length), pubKeyBytes - 1);
    } catch (std::runtime_error& e) {
        throw e;
        return "";
    }
    std::vector<unsigned char> paddedVec(padded.begin(), padded.end());
    BigInt converted;
    import_bits(converted, paddedVec.begin(), paddedVec.end());

    BigInt encrypted = boost::multiprecision::powm(converted, e, publicKey);

    if (compressedAsciiOutput) {
        return toAsciiCompressedStr(encrypted);
    }

    // Otherwise, return large (not base64-style) ASCII string
    return toAsciiStr(encrypted);
}

std::string RSA::decrypt(const std::string& message, bool compressedAsciiInput) {
    if (!privateKey) {
        throw std::runtime_error("No private key!");
        return "";
    }

    std::string decrypted = "";
    std::string chunk = "";

    // Assemble and decrypt the chunks
    for (const char& c : message) {
        if (c == '|') {
            BigInt chunkInt;
            if (compressedAsciiInput) {
                chunkInt = fromAsciiCompressedStr(chunk);
            } else
                BigInt chunkInt = fromAsciiStr(chunk);

            BigInt decryptedChunk = boost::multiprecision::powm(chunkInt, privateKey, publicKey);

            std::vector<unsigned char> beforeUnpadVec;
            export_bits(decryptedChunk, std::back_inserter(beforeUnpadVec), 8);
            std::string beforeUnpad(beforeUnpadVec.begin(), beforeUnpadVec.end());
            std::string unpadded = OAEP::unpad(beforeUnpad, pubKeyBytes - 1);

            decrypted += unpadded;
            chunk = "";
        } else {
            chunk += c;
        }
    }

    // In case string does not terminate with '|'
    if (!chunk.empty()) {
        BigInt chunkInt;
        if (compressedAsciiInput) {
            chunkInt = fromAsciiCompressedStr(chunk);
        } else
            chunkInt = fromAsciiStr(chunk);

        BigInt decryptedChunk = boost::multiprecision::powm(chunkInt, privateKey, publicKey);

        std::vector<unsigned char> beforeUnpadVec;
        export_bits(decryptedChunk, std::back_inserter(beforeUnpadVec), 8);
        std::string beforeUnpad(beforeUnpadVec.begin(), beforeUnpadVec.end());

        std::string unpadded = OAEP::unpad(beforeUnpad, pubKeyBytes - 1);

        decrypted += unpadded;
    }

    return decrypted;
}

std::string RSA::sign(const std::string& message) {
    if (!privateKey) {
        throw std::runtime_error("No private key!");
        return "";
    }

    char hash[HASH_BYTES];
    Hashing::hash(hash, message.c_str(), message.length());

    std::string signOpS = "";

    BigInt hashInt;
    import_bits(hashInt, hash, hash + HASH_BYTES);
    BigInt mod = boost::multiprecision::powm(hashInt, privateKey, publicKey);
    std::string signProof = toAsciiCompressedStr(mod);

    return "----- BEGIN RSA SIGNED MESSAGE -----\n" + message + "\n----- BEGIN RSA SIGNATURE -----\n" + signProof +
           "\n----- END RSA SIGNATURE -----\n" + "----- END RSA SIGNED MESSAGE -----\n";
}

bool RSA::verify(const std::string& signedMessage) {
    if (!publicKey) {
        throw std::runtime_error("No public key!");
        return false;
    }

    const char* cstr = signedMessage.c_str();
    const char *cur, *sigStart, *sigEnd;

    if (!(cur = strstr(cstr, "----- BEGIN RSA SIGNED MESSAGE -----\n"))) {
        throw std::runtime_error("Could not find start of signed message.");
    }

    if (!(sigStart = strstr(cur, "\n----- BEGIN RSA SIGNATURE -----\n"))) {
        throw std::runtime_error("Could not find start of signature.");
    }

    if (!(sigEnd = strstr(sigStart, "\n----- END RSA SIGNATURE -----\n"))) {
        throw std::runtime_error("Could not find end of signature.");
    }

    size_t msgSz = sigStart - cur - 37; // 37 is the size of "----- BEGIN RSA SIGNED MESSAGE -----\n"
    sigStart += 33;                     // Must do this AFTER the above line, obviously, so don't move it!

    char* msg = new char[msgSz + 1];
    memcpy(msg, cur + 37, msgSz);
    char expectedHash[HASH_BYTES];
    Hashing::hash(expectedHash, msg, msgSz);

    std::string sig(sigStart, sigEnd - sigStart);
    BigInt sigInt = fromAsciiCompressedStr(sig);
    BigInt sigHash = boost::multiprecision::powm(sigInt, e, publicKey);
    BigInt expHash;
    import_bits(expHash, expectedHash, expectedHash + HASH_BYTES);

    delete[] msg;

    return sigHash == expHash;
}

std::string RSA::getPrivateKey() const {
    std::vector<unsigned char> privKeyVec;
    export_bits(privateKey, std::back_inserter(privKeyVec), 8);
    std::string privKeyStr(privKeyVec.begin(), privKeyVec.end());
    return privKeyStr;
}

std::string RSA::getPublicKey() const {
    std::vector<unsigned char> pubKeyVec;
    export_bits(publicKey, std::back_inserter(pubKeyVec), 8);
    std::string pubKeyStr(pubKeyVec.begin(), pubKeyVec.end());
    return pubKeyStr;
}

std::string RSA::toAsciiStr(BigInt n) {
    std::stringstream builder;

    // n > 0 because -1 >> anything == -1
    for (unsigned char c = static_cast<unsigned char>((uint8_t)(n & 0x0F)) + 'J'; n > 0;
         n >>= 4, c = static_cast<unsigned char>(((uint8_t)(n & 0x0F)) + 'J')) {
        builder << c;
    }

    return builder.str();
}

BigInt RSA::fromAsciiStr(const std::string& str) {
    BigInt result = 0;
    uint64_t shift = 0;

    for (const char& c : str) {
        result |= (BigInt(c - 'J') << shift);
        shift += 4;
    }

    return result;
}

uint16_t RSA::getPublicKeyLength() const { return pubKeyBits; }

bool RSA::exportToFile(const char* filepath, bool exportPrivateKey) {
    if (exportPrivateKey && !privateKey) {
        throw std::runtime_error("No private key!");
        return false;
    }

    FILE* f = fopen(filepath, "wb");
    if (!f) {
        throw std::runtime_error("Could not open file. Error code: " + std::to_string(errno));
        return false;
    }

    if (exportPrivateKey) {
        if (!fwrite("----- RSA PRIVATE KEY -----\n", 1, 28, f)) {
            std::cout << "Could not write to file.";
            return false;
        }

        std::vector<unsigned char> privKeyVec;
        export_bits(privateKey, std::back_inserter(privKeyVec), 8);
        std::string privKeyStr(privKeyVec.begin(), privKeyVec.end());
        if (!fwrite(privKeyStr.c_str(), 1, privKeyVec.size(), f)) {
            std::cout << "Could not write to file.";
            return false;
        }

        if (!fwrite("----- END RSA PRIVATE KEY -----\n", 1, 32, f)) {
            std::cout << "Could not write to file.";
            return false;
        }
    }

    if (!fwrite("----- RSA PUBLIC KEY -----\n", 1, 27, f)) {
        std::cout << "Could not write to file.";
        return false;
    }

    std::vector<unsigned char> pubKeyVec;
    export_bits(publicKey, std::back_inserter(pubKeyVec), 8);
    std::string pubKeyStr(pubKeyVec.begin(), pubKeyVec.end());
    if (!fwrite(pubKeyStr.c_str(), 1, pubKeyVec.size(), f)) {
        std::cout << "Could not write to file.";
        return false;
    }

    if (!fwrite("----- END RSA PUBLIC KEY -----\n", 1, 31, f)) {
        std::cout << "Could not write to file.";
        return false;
    }

    if (fclose(f)) {
        throw std::runtime_error("Could not close file. Error code: " + std::to_string(errno));
        return false;
    }

    return true;
}

std::string RSA::exportToString(bool exportPrivateKey) {
    if (exportPrivateKey && !privateKey) {
        throw std::runtime_error("No private key!");
        return "";
    }

    std::string result = "";

    if (exportPrivateKey) {
        result += "----- RSA PRIVATE KEY -----\n";

        result += toAsciiCompressedStr(privateKey);

        result += "----- END RSA PRIVATE KEY -----\n";
    }

    result += "----- RSA PUBLIC KEY -----\n";

    result += toAsciiCompressedStr(publicKey);

    result += "----- END RSA PUBLIC KEY -----\n";

    return result;
}

std::string RSA::getFingerprint() {
    if (!publicKey) {
        throw std::runtime_error("No public key!");
        return "";
    }

    static char hash[HASH_BYTES];
    std::vector<char> pubKeyVec;
    export_bits(publicKey, std::back_inserter(pubKeyVec), 8);
    Hashing::hash(hash, reinterpret_cast<const char*>(pubKeyVec.data()), pubKeyVec.size());

    return toAsciiCompressedStr(reinterpret_cast<const uint8_t*>(hash), HASH_BYTES);
}

bool RSA::importFromFile(const char* filepath, bool importPrivateKey) {
    FILE* f = fopen(filepath, "rb+");

    if (!f) {
        throw std::runtime_error("Could not open file. Error code: " + std::to_string(errno));
        return false;
    }

    fseek(f, 0, SEEK_END);
    size_t fileSize = ftell(f);
    rewind(f);

    char* fileContents = new char[fileSize + 1];
    if (!fileContents) {
        throw std::runtime_error("Could not allocate memory for file contents.");
        return false;
    }

    size_t success = fread(fileContents, 1, fileSize, f);

    if (!success) {
        throw std::runtime_error("Could not read from file.");
        return false;
    }

    if (fclose(f)) {
        throw std::runtime_error("Could not close file. Error code: " + std::to_string(errno));
        return false;
    }

    fileContents[success] = '\0';

    if (importPrivateKey) {
        char* privStart;

        if (!(privStart = strstr(fileContents, "----- RSA PRIVATE KEY -----\n"))) {
            throw std::runtime_error("Could not find private key in file.");
            return false;
        }

        privStart += 28;

        char* privEnd = reinterpret_cast<char*>(memmem(reinterpret_cast<const void*>(privStart), success - (privStart - fileContents),
                                                       reinterpret_cast<const void*>("----- END RSA PRIVATE KEY -----\n"), 32));
        if (!privEnd) {
            throw std::runtime_error("Could not find end of private key in file.");
            return false;
        }

        std::vector<unsigned char> privKeyVec;
        privKeyVec.reserve(privEnd - privStart);

        for (const char* c = privStart; c < privEnd; c++) {
            privKeyVec.push_back(*c);
        }

        import_bits(this->privateKey, privKeyVec.begin(), privKeyVec.end());
    }

    char* pubStart;
    if (!(pubStart = reinterpret_cast<char*>(memmem(fileContents, success, "----- RSA PUBLIC KEY -----\n", 27)))) {
        throw std::runtime_error("Could not find public key in file.");
        return false;
    }

    pubStart += 27;

    char* pubEnd = reinterpret_cast<char*>(memmem(pubStart, success - (pubStart - fileContents), "----- END RSA PUBLIC KEY -----\n", 31));
    if (!pubEnd) {
        throw std::runtime_error("Could not find end of public key in file.");
        return false;
    }

    std::vector<unsigned char> pubKeyVec;
    pubKeyVec.reserve(pubEnd - pubStart);
    for (char* c = pubStart; c < pubEnd; c++) {
        pubKeyVec.push_back(*c);
    }

    import_bits(this->publicKey, pubKeyVec.begin(), pubKeyVec.end());
    this->pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    this->pubKeyBytes = this->pubKeyBits >> 3;

    return true;
}

bool RSA::importFromString(const std::string& s, bool importPrivateKey) {
    const char* fileContents = s.c_str();
    size_t success = s.size();

    if (importPrivateKey) {
        const char* privStart;

        if (!(privStart = strstr(fileContents, "----- RSA PRIVATE KEY -----\n"))) {
            throw std::runtime_error("Could not find private key in file.");
            return false;
        }

        privStart += 28;

        char* privEnd = reinterpret_cast<char*>(memmem(reinterpret_cast<const void*>(privStart), success - (privStart - fileContents),
                                                       reinterpret_cast<const void*>("----- END RSA PRIVATE KEY -----\n"), 32));
        if (!privEnd) {
            throw std::runtime_error("Could not find end of private key in file.");
            return false;
        }

        // Get an std::string for the private key (for passing to fromAsciiCompressedStr())
        std::string privKeyStr(privStart, privEnd - privStart);
        this->privateKey = fromAsciiCompressedStr(privKeyStr);
    }

    char* pubStart;
    if (!(pubStart = reinterpret_cast<char*>(memmem(fileContents, success, "----- RSA PUBLIC KEY -----\n", 27)))) {
        throw std::runtime_error("Could not find public key in file.");
        return false;
    }

    pubStart += 27;

    char* pubEnd = reinterpret_cast<char*>(memmem(pubStart, success - (pubStart - fileContents), "----- END RSA PUBLIC KEY -----\n", 31));
    if (!pubEnd) {
        throw std::runtime_error("Could not find end of public key in file.");
        return false;
    }

    std::string pubKeyStr(pubStart, pubEnd - pubStart);

    this->publicKey = fromAsciiCompressedStr(pubKeyStr);
    this->pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    this->pubKeyBytes = this->pubKeyBits >> 3;

    return true;
}

RSA RSA::empty() { return RSA(); }

#ifdef DEBUG_TESTING
void RSA::testLCG() {
    for (int i = 0; i < 10000; i++) {
        std::cout << lcg.next() << "\n";
    }
}

void RSA::testPrimeDetection(BigInt n) {
    if (this->rabinMillerIsPrime(n, 10)) {
        std::cout << n << " is probably prime!"
                  << "\n";
    } else {
        std::cout << n << " is not prime!"
                  << "\n";
    }
}

void RSA::testPrimeGeneration(uint16_t keyLength) {
    BigInt prime = this->generatePrime(keyLength);

    std::cout << prime << "\n";
}
#endif

RSA RSA::buildFromString(const std::string& s, bool importPrivateKey) {
    RSA rsa;

    try {
        if (rsa.importFromString(s, importPrivateKey)) {
            return rsa;
        }
    } catch (std::runtime_error& e) {
        return {};
    }

    throw std::runtime_error("Could not build RSA object from string.");
}

bool RSA::isEmpty() { return (!publicKey && !privateKey); }

bool RSA::hasPrivate() { return static_cast<bool>(privateKey); }

// Bind the RSA class to the JS environment
EMSCRIPTEN_BINDINGS(MyRSA) {
    class_<RSA>("MyRSA")
        .constructor<uint16_t>()
        .constructor<RsaKey, RsaKey>()
        .property("publicKey", &RSA::getPublicKey)
        .property("privateKey", &RSA::getPrivateKey)
        .property("publicKeyLength", &RSA::getPublicKeyLength)
        .class_function("empty", &RSA::empty)
        .class_function("buildFromKeyFile", &RSA::buildFromKeyFile, allow_raw_pointers())
        .class_function("buildFromString", &RSA::buildFromString, allow_raw_pointers())
        .function("encrypt", &RSA::encrypt)
        .function("decrypt", &RSA::decrypt)
        .function("exportToString", &RSA::exportToString, allow_raw_pointers())
        .function("importFromFile", &RSA::importFromFile, allow_raw_pointers())
        .function("importFromString", &RSA::importFromString, allow_raw_pointers())
        .function("isEmpty", &RSA::isEmpty)
        .function("hasPrivate", &RSA::hasPrivate)
        .function("sign", &RSA::sign)
        .function("verify", &RSA::verify)
        .function("getFingerprint", &RSA::getFingerprint);
}
