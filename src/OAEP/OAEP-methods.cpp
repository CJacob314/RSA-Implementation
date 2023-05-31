#include "../OAEP.h"

std::string OAEP::pad(std::string message, uint16_t keyLength){
    /* TODO
        Implement this based on my hashing algorithm (https://github.com/CJacob314/My-First-Hash) and this page: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
        MGF1 is defined pretty decently here starting on page 42: http://www.di-srv.unisa.it/~ads/corso-security/www/CORSO-9900/oracle/pkcsv21.pdf
    */

   std::cerr << "OAEP::pad() not implemented yet\n";
   throw new std::runtime_error("OAEP::pad() not implemented yet");
}