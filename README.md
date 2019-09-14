#  Anonymous Atomic Locks (A2L)

A2L [1] is a secure, privacy-preserving, interoperable, and fungibility-preserving PCH. A2L builds on a novel cryptographic primitive 
that realizes a three-party protocol for conditional transactions, where the intermediary pays the receiver only if the latter solves a cryptographic 
challenge with the help of the sender. A2L can be instantiated using either Schnorr or ECDSA signature.

## Dependencies

* [CMake](https://cmake.org/download/) >= 3.12
* [GMP](https://gmplib.org/) >= 6.1.2
* [RELIC](https://github.com/relic-toolkit/relic) (configured with `-DBN_PRECI=4096` and `-DARITH=gmp`)

## Warning

This code has **not** received sufficient peer review by other qualified cryptographers to be considered in any way, shape, or form, safe. 
It was developed for experimentation purposes.

**USE AT YOUR OWN RISK**

## References

[1]  Erkan Tairi, Pedro-Moreno Sanchez, and Matteo Maffei, "[A2L: Anonymous Atomic Locks for Scalability and Interoperability in Payment Channel Hubs](https://eprint.iacr.org/2019/589)".
