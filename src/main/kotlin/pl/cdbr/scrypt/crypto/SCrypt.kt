// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package pl.cdbr.scrypt.crypto

import pl.cdbr.scrypt.Extensions.and
import java.lang.Integer.MAX_VALUE
import java.lang.System.arraycopy
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor


/**
 * An implementation of the [scrypt](http://www.tarsnap.com/scrypt/scrypt.pdf)
 * key derivation function.
 *
 * @author  Will Glozer, Michał Nowak
 */
@Suppress("SameParameterValue")
object SCrypt {

    /**
     * Pure Java implementation of the [](http://www.tarsnap.com/scrypt/scrypt.pdf)scrypt KDF.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException when HMAC_SHA256 is not available.
     */
    @Throws(GeneralSecurityException::class)
    fun scrypt(passwd: ByteArray, salt: ByteArray, N: Int, r: Int, p: Int, dkLen: Int): ByteArray {
        if (N < 2 || N and N - 1 != 0) throw IllegalArgumentException("N must be a power of 2 greater than 1")

        if (N > MAX_VALUE / 128 / r) throw IllegalArgumentException("Parameter N is too large")
        if (r > MAX_VALUE / 128 / p) throw IllegalArgumentException("Parameter r is too large")

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(passwd, "HmacSHA256"))

        val DK = ByteArray(dkLen)

        val B = ByteArray(128 * r * p)
        val XY = ByteArray(256 * r)
        val V = ByteArray(128 * r * N)
        var i: Int

        PBKDF.pbkdf2(mac, salt, 1, B, p * 128 * r)

        i = 0
        while (i < p) {
            smix(B, i * 128 * r, r, N, V, XY)
            i++
        }

        PBKDF.pbkdf2(mac, B, 1, DK, dkLen)

        return DK
    }

    private fun smix(B: ByteArray, Bi: Int, r: Int, N: Int, V: ByteArray, XY: ByteArray) {
        val Xi = 0
        val Yi = 128 * r
        var i: Int

        arraycopy(B, Bi, XY, Xi, 128 * r)

        i = 0
        while (i < N) {
            arraycopy(XY, Xi, V, i * (128 * r), 128 * r)
            blockmix_salsa8(XY, Xi, Yi, r)
            i++
        }

        i = 0
        while (i < N) {
            val j = integerify(XY, Xi, r) and N - 1
            blockxor(V, j * (128 * r), XY, Xi, 128 * r)
            blockmix_salsa8(XY, Xi, Yi, r)
            i++
        }

        arraycopy(XY, Xi, B, Bi, 128 * r)
    }

    private fun blockmix_salsa8(BY: ByteArray, Bi: Int, Yi: Int, r: Int) {
        val X = ByteArray(64)
        var i: Int

        arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64)

        i = 0
        while (i < 2 * r) {
            blockxor(BY, i * 64, X, 0, 64)
            salsa20_8(X)
            arraycopy(X, 0, BY, Yi + i * 64, 64)
            i++
        }

        i = 0
        while (i < r) {
            arraycopy(BY, Yi + i * 2 * 64, BY, Bi + i * 64, 64)
            i++
        }

        i = 0
        while (i < r) {
            arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64)
            i++
        }
    }

    private fun R(a: Int, b: Int): Int {
        return a shl b or a.ushr(32 - b)
    }

    private fun salsa20_8(B: ByteArray) {
        val B32 = IntArray(16)
        val x = IntArray(16)
        var i: Int

        i = 0
        while (i < 16) {
            B32[i] = B[i * 4 + 0] and 0xff shl 0
            B32[i] = B32[i] or (B[i * 4 + 1] and 0xff shl 8)
            B32[i] = B32[i] or (B[i * 4 + 2] and 0xff shl 16)
            B32[i] = B32[i] or (B[i * 4 + 3] and 0xff shl 24)
            i++
        }

        arraycopy(B32, 0, x, 0, 16)

        i = 8
        while (i > 0) {
            x[4] = x[4] xor R(x[0] + x[12], 7)
            x[8] = x[8] xor R(x[4] + x[0], 9)
            x[12] = x[12] xor R(x[8] + x[4], 13)
            x[0] = x[0] xor R(x[12] + x[8], 18)
            x[9] = x[9] xor R(x[5] + x[1], 7)
            x[13] = x[13] xor R(x[9] + x[5], 9)
            x[1] = x[1] xor R(x[13] + x[9], 13)
            x[5] = x[5] xor R(x[1] + x[13], 18)
            x[14] = x[14] xor R(x[10] + x[6], 7)
            x[2] = x[2] xor R(x[14] + x[10], 9)
            x[6] = x[6] xor R(x[2] + x[14], 13)
            x[10] = x[10] xor R(x[6] + x[2], 18)
            x[3] = x[3] xor R(x[15] + x[11], 7)
            x[7] = x[7] xor R(x[3] + x[15], 9)
            x[11] = x[11] xor R(x[7] + x[3], 13)
            x[15] = x[15] xor R(x[11] + x[7], 18)
            x[1] = x[1] xor R(x[0] + x[3], 7)
            x[2] = x[2] xor R(x[1] + x[0], 9)
            x[3] = x[3] xor R(x[2] + x[1], 13)
            x[0] = x[0] xor R(x[3] + x[2], 18)
            x[6] = x[6] xor R(x[5] + x[4], 7)
            x[7] = x[7] xor R(x[6] + x[5], 9)
            x[4] = x[4] xor R(x[7] + x[6], 13)
            x[5] = x[5] xor R(x[4] + x[7], 18)
            x[11] = x[11] xor R(x[10] + x[9], 7)
            x[8] = x[8] xor R(x[11] + x[10], 9)
            x[9] = x[9] xor R(x[8] + x[11], 13)
            x[10] = x[10] xor R(x[9] + x[8], 18)
            x[12] = x[12] xor R(x[15] + x[14], 7)
            x[13] = x[13] xor R(x[12] + x[15], 9)
            x[14] = x[14] xor R(x[13] + x[12], 13)
            x[15] = x[15] xor R(x[14] + x[13], 18)
            i -= 2
        }

        i = 0
        while (i < 16) {
            B32[i] = x[i] + B32[i]
            ++i
        }

        i = 0
        while (i < 16) {
            B[i * 4 + 0] = (B32[i] shr 0 and 0xff).toByte()
            B[i * 4 + 1] = (B32[i] shr 8 and 0xff).toByte()
            B[i * 4 + 2] = (B32[i] shr 16 and 0xff).toByte()
            B[i * 4 + 3] = (B32[i] shr 24 and 0xff).toByte()
            i++
        }
    }

    private fun blockxor(S: ByteArray, Si: Int, D: ByteArray, Di: Int, len: Int) {
        for (i in 0 until len) {
            D[Di + i] = D[Di + i] xor S[Si + i]
        }
    }

    private fun integerify(B: ByteArray, BiIn: Int, r: Int): Int {
        var Bi = BiIn
        var n: Int

        Bi += (2 * r - 1) * 64

        n = B[Bi + 0] and 0xff shl 0
        n = n or (B[Bi + 1] and 0xff shl 8)
        n = n or (B[Bi + 2] and 0xff shl 16)
        n = n or (B[Bi + 3] and 0xff shl 24)

        return n
    }
}
