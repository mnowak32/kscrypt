// Copyright (C) 2011 - Will Glozer.  All rights reserved.
// Copyright (C) 2019 - Michał Nowak.  All rights reserved.

package pl.cdbr.scrypt.crypto

import com.lambdaworks.codec.Base64.decode
import com.lambdaworks.codec.Base64.encode
import java.io.UnsupportedEncodingException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import kotlin.experimental.or
import kotlin.experimental.xor
import kotlin.math.pow

/**
 * Simple [SCrypt] interface for hashing passwords using the
 * [scrypt](http://www.tarsnap.com/scrypt.html) key derivation function
 * and comparing a plain text password to a hashed one. The hashed output is an
 * extended implementation of the Modular Crypt Format that also includes the scrypt
 * algorithm parameters.
 *
 * Format: `$s0$PARAMS$SALT$KEY`.
 *
 * <dl>
 * <dd>PARAMS</dd><dt>32-bit hex integer containing log2(N) (16 bits), r (8 bits), and p (8 bits)</dt>
 * <dd>SALT</dd><dt>base64-encoded salt</dt>
 * <dd>KEY</dd><dt>base64-encoded derived key</dt>
</dl> *
 *
 * `s0` identifies version 0 of the scrypt format, using a 128-bit salt and 256-bit derived key.
 *
 * @author  Will Glozer, Michał Nowak
 */
@Suppress("unused")
object SCryptUtil {
    private const val dkLen = 32
    private val chSet = Charsets.UTF_8
    private const val byteZero = 0.toByte()

    /**
     * Hash the supplied plaintext password and generate output in the format described
     * in [SCryptUtil].
     *
     * @param passwd    Password.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     *
     * @return The hashed password.
     */
    fun scrypt(passwd: String, N: Int, r: Int, p: Int): String {
        try {
            val salt = ByteArray(16)
            SecureRandom.getInstance("SHA1PRNG").nextBytes(salt)

            val derived = SCrypt.scrypt(passwd.toByteArray(chSet), salt, N, r, p, dkLen)

            val params = (log2(N) shl 16 or (r shl 8) or p).toLong().toString(16)

            return "\$s0\$$params\$${String(encode(salt))}\$${String(encode(derived))}"

        } catch (e: UnsupportedEncodingException) {
            throw IllegalStateException("JVM doesn't support UTF-8?")
        } catch (e: GeneralSecurityException) {
            throw IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?")
        }

    }

    /**
     * Compare the supplied plaintext password to a hashed password.
     *
     * @param   passwd  Plaintext password.
     * @param   hashed  scrypt hashed password.
     *
     * @return true if passwd matches hashed value.
     */
    fun check(passwd: String, hashed: String): Boolean {
        try {
            val parts = hashed.split("\\$".toRegex()).dropLastWhile { it.isEmpty() }

            if (parts.size != 5 || parts[1] != "s0") {
                throw IllegalArgumentException("Invalid hashed value")
            }

            val params = parts[2].toLong(16)
            val salt = decode(parts[3].toCharArray())
            val derived0 = decode(parts[4].toCharArray())

            val n = 2.0.pow((params shr 16 and 0xffff).toDouble()).toInt()
            val r = params.toInt() shr 8 and 0xff
            val p = params.toInt() and 0xff

            val derived1 = SCrypt.scrypt(passwd.toByteArray(chSet), salt, n, r, p, dkLen)

            return derived0.contentEquals(derived1)
        } catch (e: UnsupportedEncodingException) {
            throw IllegalStateException("JVM doesn't support UTF-8?")
        } catch (e: GeneralSecurityException) {
            throw IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?")
        }

    }

    private fun log2(nIn: Int): Int {
        var n = nIn
        var log = 0
        if (n and -0x10000 != 0) {
            n = n ushr 16
            log = 16
        }
        if (n >= 256) {
            n = n ushr 8
            log += 8
        }
        if (n >= 16) {
            n = n ushr 4
            log += 4
        }
        if (n >= 4) {
            n = n ushr 2
            log += 2
        }
        return log + n.ushr(1)
    }
}
