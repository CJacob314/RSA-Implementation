# This Branch
This branch is different as I have not used my own implementations for many big integer functions like I did on all other branches. Specifically, I switched over to Boost's implementations for modular exponentiation, modular multiplicative inverse calculation, and the Rabin Miller primality test.

## My Own Implementation of the RSA Cryptosystem

### Inspired by Professor Looper at [UIC](https://mscs.uic.edu/profiles/nrlooper/), who instructed my amazing Math 215 course.

This implementation uses only the standard C++ library and [Boost Multiprecision integers](https://www.boost.org/doc/libs/1_82_0/libs/multiprecision/doc/html/boost_multiprecision/tut/ints/cpp_int.html).

---

# **Try It Online With Web Assembly Now** [here](https://rsa.jacobcohen.dev/)!

This online version of my RSA implementation runs entirely in your browser, client-side, with [Web Assembly](https://webassembly.org/) and a bit of Javascript I wrote.

It uses code from [the emscripten branch](https://github.com/CJacob314/RSA-Implementation/tree/emscripten) of this repository, which is (you guessed it) compiled with [emscripten](https://emscripten.org/).