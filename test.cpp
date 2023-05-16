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
    uint16_t bits = 16;
    std::cout << "Generating " << bits << "-bit RSA keypair...\n";
    RSA rsa(bits);

    std::cout << "Generated. Enter EOF-terminated message to encrypt:\n";
    
    std::istreambuf_iterator<char> begin(std::cin), end;
    std::string message(begin, end);
    
    RSA pubOnly(rsa.getPublicKey());

    std::cout << "Encrypting inputted string with the public key...\n";
    std::string encrypted = pubOnly.encrypt(message);

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
