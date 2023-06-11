#include "../RSA.h"
#include "../Utilities.h"

bool RSA::operator!(){
    return (!publicKey && !privateKey);
}
