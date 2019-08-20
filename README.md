kscrypt
=======

A Kotlin conversion of a [pure Java implementation](https://github.com/wg/scrypt)
of [scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf).

All kudos go to Will Gozer, the original author of the Java `scrypt`.

I've removed the whole JNI part of the original as I don't need it.

Original tests pass except for `SCryptTest.scrypt_paper_appendix_b()`, which reslts in OOM on my machine...

See [Original README](README.orig).