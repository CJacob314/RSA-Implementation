# Notes on This Branch
This branch is based on my [max-speed](https://github.com/CJacob314/RSA-Implementation/tree/max-speed) branch, but made to work on WebAssembly. As such, this branch **does not have** my own implementations for the Rabin Miller primality test or modular multiplicative inverse and modular exponentiation calculation. You can find *my* implementations of those functions on the [main branch](https://github.com/CJacob314/RSA-Implementation/tree/main) or the [multithreaded branch](https://github.com/CJacob314/RSA-Implementation/tree/multithreaded).

## My Own Implementation of the RSA Cryptosystem

### Inspired by Professor Looper at [UIC](https://mscs.uic.edu/profiles/nrlooper/), who instructed my amazing Math 215 course.

This implementation uses only the standard C++ library and [Boost Multiprecision integers](https://www.boost.org/doc/libs/1_82_0/libs/multiprecision/doc/html/boost_multiprecision/tut/ints/cpp_int.html).