#include "../RSA.h"
#include "../Utilities.h"

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

    std::cout << "p: " << p << "\nq: " << q << "\nphi(p*q): " 
        << phi << "\nPublicKey(n=p*q): " << publicKey << "\nprivateKey: " << privateKey << "\n";
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