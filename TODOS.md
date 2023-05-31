# TODO LIST
-----

1. ~~Make sure that the message $m$ is chunked into pieces $p_i$ such that $p_i < n,$ $\forall p_i$ (for $n=pq$, for large primes $p, q$).~~
2. ~~Add conversions to and from **ASCII** strings for the type `BigInt`.~~
    * ~~My idea is currently to chunk each byte (`b`) of the `BigInt` into $2$ characters, found by~~
        * ~~`c1 = (b >> 4) + 0x21`~~
        * ~~`c2 = (b & 0x0F) + 0x21`~~
3. Implement [**optimal asymmetric encryption padding**](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
4. Add additional encryption and decryption methods which do not return the extra long `std::string`. I will choose between returning a `BigInt`, writing to a byte buffer (`uint8_t[]`) and only returning success status, or implementing both.
5. Add full command line interface for encryption and decryption.
