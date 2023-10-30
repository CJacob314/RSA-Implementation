#include "../RSA.h"
#include "../Utilities.h"

RSA::RSA(uint16_t newKeyLength) {
    if (newKeyLength < 1024) {
        throw std::runtime_error("Key length must be at least 1024 bits!");
        return;
    }

    // Create a thread pool (I do create and destroy it every time, which is inefficient for multiple key generations) for prime number searching
    std::vector<std::thread> searchThreads(Num_Prime_Search_Threads);

    size_t i = 0;
    for (auto& t : searchThreads) {
        // Attempt to be close to the desired bit count by splitting in half the tasks which were once done once.
        // If the two which finish first are both numbered even or odd, then we will be a little bit off, but that should be okay.
        t = std::thread(&RSA::generatePrime, this, (i++ % 2 == 1) ? ((newKeyLength >> 1) + (ODD(newKeyLength) ? 1 : 0)) : (newKeyLength >> 1));
    }

    { // Scope braces to ensure that the lock is released as soon as the cv.wait call is done (as opposed to when the constructor returns).
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this] { return primesFound >= 2 || stopFlag.load(); });
    }

    for (auto& thread : searchThreads) {
        if (thread.joinable()) thread.join();
    }

    // Proceed as normal generating the RSA key
    publicKey = primes[0] * primes[1];

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = (pubKeyBits < 8) ? 1 : pubKeyBits >> 3;

    BigInt phi = (primes[0] - 1) * (primes[1] - 1);
    privateKey = modInv(e, phi);

#ifdef DEBUG_TESTING
    std::cout << "p: " << primes[0] << "\n\nq: " << primes[1] << "\n\nphi(p*q): " << phi << "\n\nPublicKey(n=p*q): " << publicKey
              << "\n\nprivateKey: " << privateKey << "\n";
#endif
}

RSA::RSA(RsaKey privateKey, RsaKey publicKey) {
    this->privateKey = privateKey;
    this->publicKey = publicKey;

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = pubKeyBits >> 3;
}

RSA::RSA(RsaKey publicKey) {
    this->publicKey = publicKey;

    pubKeyBits = boost::multiprecision::msb(publicKey) + 1;
    pubKeyBytes = pubKeyBits >> 3;
}

std::optional<RSA> RSA::buildFromKeyFile(const char* filepath, bool importPrivateKey) {
    RSA rsa;

    try {
        if (rsa.importFromFile(filepath, importPrivateKey)) {
            return std::make_optional(std::move(rsa));
        } else {
            return std::nullopt;
        }
    } catch (std::runtime_error& e) {
        return {};
    }
}

// Move constructor
RSA::RSA(RSA&& other) noexcept
    : Num_Prime_Search_Threads(std::move(other.Num_Prime_Search_Threads)),
      primes(std::move(other.primes)),
      privateKey(std::move(other.privateKey)),
      publicKey(std::move(other.publicKey)),
      pubKeyBytes(std::move(other.pubKeyBytes)),
      pubKeyBits(std::move(other.pubKeyBits)) {}
