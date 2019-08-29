kscrypt
=======

A Kotlin conversion of a [pure Java implementation](https://github.com/wg/scrypt)
of [scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf).

All kudos go to Will Gozer, the original author of the Java `scrypt`.

I've removed the whole JNI part of the original as I don't need it. Also
dropped a custom `Base64` implementation in favour of the JRE one.

~~Original tests pass except for `SCryptTest.scrypt_paper_appendix_b()`, which reslts in OOM on my machine...~~
UPDATE: after increasing `maxHeapSize` setting to 2GiB for the `test` Gradle task, it passes now 100%.

See [Original README](README.orig).