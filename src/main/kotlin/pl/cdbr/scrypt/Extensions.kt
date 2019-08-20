package pl.cdbr.scrypt

/**
 * Some helper Kotlin functions to allow writing bitwise operations a *bit* shorter :)
 *
 * @author Michał Nowak
 */
internal object Extensions {
    fun byte(i: Int) = i.toByte()
    operator fun IntArray.get(i: Char) = this[i.toInt()]
    operator fun CharArray.get(i: Byte) = this[i.toInt()]
    operator fun ByteArray.get(i: Byte) = this[i.toInt()]
    infix fun Byte.shl(b: Byte) = byte(this.toInt() shl b.toInt())
    infix fun Byte.ushr(b: Byte) = byte(this.toInt() ushr b.toInt())
    infix fun Byte.and(i: Int) = this.toInt() and i
}