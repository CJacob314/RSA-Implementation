## My Own Implementation of the RSA Cryptosystem

### Inspired by Professor Looper at [UIC](https://mscs.uic.edu/profiles/nrlooper/), who instructed my amazing Math 215 course.

This implementation uses only the C++ STL and [Boost Multiprecision integers](https://www.boost.org/doc/libs/1_82_0/libs/multiprecision/doc/html/boost_multiprecision/tut/ints/cpp_int.html). In this branch (and [main](../../tree/main)), I only used  `boost::multiprecision::cpp_int` for large integer addition, subtraction, multiplication, division, and modulo. I implemented the Rabin Miller primality test, modular exponentiation, and modular multiplicative inverse calculation myself.

---

# **Try It Online With Web Assembly Now** [here](https://rsa.jacobcohen.dev/)!

This online version of my RSA implementation runs entirely in your browser, client-side, with [Web Assembly](https://webassembly.org/) and a bit of Javascript I wrote.

It uses code from [the emscripten branch](https://github.com/CJacob314/RSA-Implementation/tree/emscripten) of this repository, which is (you guessed it) compiled with [emscripten](https://emscripten.org/).
