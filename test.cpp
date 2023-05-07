#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <random>
#include <cmath>
#include "src/RSA.h"

int main(void){
    std::cout << "Generating 4096-bit RSA keypair...\n";
    RSA rsa(4096);
    std::cout << "DONE. Enter a message to encrypt, terminating with EOF.\n";
    
    std::istreambuf_iterator<char> begin(std::cin), end;
    std::string message(begin, end);
    
    RSA pubOnly(rsa.getPublicKey());

    std::cout << "Encrypting inputted string with the public key...\n";
    BigInt encrypted = pubOnly.encrypt(message);

    std::cout << "ENCRYPTED MESSAGE BELOW...\n" << encrypted << "\nAttempting decrypt with public key only class (should FAIL)...\n";

    try{
        std::cout << pubOnly.decrypt(encrypted) << "\nNow decrypting with private key class...\n";
    } catch(std::runtime_error& e){
        std::cout << "Failed. Exception what():\t" << e.what() << "\n";
    }

    std::cout << "Now trying with the private key class...\n";

    std::string decrypted = rsa.decrypt(encrypted);

    std::cout << "DECRYPTED:\n\n" << decrypted << "\n";

    return 0;
}