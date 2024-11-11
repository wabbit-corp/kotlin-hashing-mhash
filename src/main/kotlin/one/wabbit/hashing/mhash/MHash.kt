@file:OptIn(ExperimentalUnsignedTypes::class)
package one.wabbit.hashing.mhash

/**
 *
 * https://www.youtube.com/watch?v=zQB1erzYxdI
 * https://www.rocq.inria.fr/secret/Jean-Pierre.Tillich/publications/HashingSL2.pdf
 * https://www.iacr.org/archive/crypto2000/18800288/18800288.pdf
 * http://lib.dr.iastate.edu/cgi/viewcontent.cgi?article=15807&context=rtd
 * https://www.youtube.com/watch?v=hJCv5KDMAFI
 * https://ticki.github.io/blog/designing-a-good-non-cryptographic-hash-function/
 */
@JvmInline
value class MHash(val value: UInt): Comparable<MHash> {

    operator fun plus(that: MHash): MHash = MHash(combineRaw(this.value, that.value))

    fun update(b: Byte): MHash = this + fromByte(b)
    fun update(b: Short): MHash = this + fromShort(b)
    fun update(b: Char): MHash = this + fromChar(b)
    fun update(b: Int): MHash = this + fromInt(b)
    fun update(b: Long): MHash = this + fromLong(b)
    fun update(b: ByteArray): MHash = this + fromByteArray(b)

    override fun toString(): String = "MHash(0x${java.lang.Integer.toHexString(value.toInt())})"
    override fun compareTo(o: MHash): Int = Integer.compareUnsigned(this.value.toInt(), o.value.toInt())

    companion object {
        @OptIn(ExperimentalUnsignedTypes::class)
        private val table: UIntArray = uintArrayOf(
            0x8cc9b9a0u, 0x58c0f709u, 0x263225a8u, 0x2be26ab7u,
            0xc63fb5a9u, 0x7de36137u, 0x3baefe17u, 0x80303abdu,
            0x5d9b25c5u, 0xf4812ceu, 0xc41976adu, 0x49c8e38eu,
            0x6d04db43u, 0x266cd9a3u, 0x26c3422du, 0xc896bde2u,
            0x2eb35c50u, 0x6dc94dceu, 0x38ca2e1bu, 0x7b8de4bdu,
            0x854896efu, 0x35d99b6au, 0xd04b6080u, 0x3c7a0efu,
            0xd43cc644u, 0x9416c57au, 0x2baa99b1u, 0xe8c52a8du,
            0x353e50d1u, 0xfea54a70u, 0xb3f14f5u, 0xf946ef59u,
            0xee1fdfb4u, 0xa7289525u, 0xd2824ab2u, 0x3f13d312u,
            0xc56ec7fu, 0x5e9c3e59u, 0xc3896183u, 0x93b6c402u,
            0xe500ae92u, 0xbaa33f08u, 0x97e0b4ddu, 0x9d5a190au,
            0x84e8ebc3u, 0x636242a2u, 0x6a2deb80u, 0x5c7620b3u,
            0x6ed46065u, 0xee8ce600u, 0x21cbc23u, 0xb8d831c2u,
            0xcf5a3956u, 0x916c6e86u, 0x13e2ceddu, 0xf1d4135eu,
            0x430b391bu, 0x4a2fcad5u, 0x7cb159dbu, 0x2ed3503bu,
            0x646a1d8du, 0x4f9ae788u, 0x7a7eac2bu, 0x2298b51u,
            0x9352c86eu, 0xe7224eaau, 0x3131c8e6u, 0xa92c6c12u,
            0x2a236e89u, 0xb4d96a46u, 0xa7dd5155u, 0xd36c8174u,
            0x58313631u, 0xe061a8deu, 0xca4c7b80u, 0x2446b2bfu,
            0x64d059d0u, 0xd1df5566u, 0x949a220u, 0x2d2036a1u,
            0x8ff1ee99u, 0x332486aeu, 0x8bdcc13bu, 0x83ed69d5u,
            0x5e48dda7u, 0xe275cc66u, 0x6a9aa174u, 0x620b8c98u,
            0xeea1eda3u, 0x6e0c8443u, 0xffd1c01eu, 0xa22f00aeu,
            0x980515fcu, 0x7e695af4u, 0xd8aa2485u, 0xe3ade969u,
            0x3a2e696eu, 0x13b79289u, 0x3536dbd6u, 0x81c3450fu,
            0xeaac75bfu, 0x68d116f9u, 0xfaed2fd0u, 0x60f60157u,
            0xcd83712bu, 0xff93848bu, 0x663f0c7eu, 0xe64b29deu,
            0x954d6f65u, 0x737dc4ffu, 0xab771f3fu, 0xb0d37342u,
            0x10f4b9b1u, 0x34e0815u, 0xde471b28u, 0x5dddbb25u,
            0x55b8c5f0u, 0x72135a10u, 0xa7f90b8eu, 0x109db701u,
            0xaf06f114u, 0x8c032f36u, 0x93f1a918u, 0x1bc0ac8du,
            0xd3a1f3c1u, 0x81a808b2u, 0x2e03365bu, 0xced289bu,
            0xb9d5ee2eu, 0xfb84e97fu, 0x74ecf139u, 0x91d834cfu,
            0x487924e1u, 0x8273d015u, 0xddcbf2beu, 0x709f24a1u,
            0x42228336u, 0x9098ec55u, 0x470cc738u, 0xaf29d3d5u,
            0xe4c668f7u, 0xa0064640u, 0xf9aa1e8bu, 0x3448d984u,
            0xf8a1575fu, 0x6e4998a6u, 0x71af37f2u, 0xaa6d23acu,
            0xc7861c42u, 0xae7c216eu, 0x6157c956u, 0x147ee9d1u,
            0x1da3037au, 0x2bdf5bafu, 0x2e644a22u, 0x4b40b3a9u,
            0xb75798b4u, 0xb1d0551bu, 0xf68161b1u, 0xf906d4f2u,
            0xb9ff589bu, 0xa985f807u, 0xac18bb95u, 0x90cfb9du,
            0x8500cf69u, 0xf595e214u, 0xe3c56df8u, 0x42b6faa6u,
            0xc51ceb24u, 0x74dcdb8cu, 0x4b22e301u, 0x7b78ba11u,
            0x47dd8267u, 0x2249e810u, 0xb7da59b2u, 0x134354adu,
            0xcb42b981u, 0x6a752f49u, 0x1c3f8062u, 0xa7c9dcc0u,
            0x64ef42bbu, 0x349d9864u, 0x2c1a0196u, 0xcda68673u,
            0x222bdfa4u, 0x5f4896bu, 0x91d1527bu, 0xc47cd3dcu,
            0xcf8ce91au, 0x8aff1884u, 0x58f3113du, 0xba1d1d2du,
            0x8510b6a0u, 0xc919e33bu, 0xfb20bf8u, 0xe8ebe37fu,
            0xcb8ff27cu, 0x2a14323au, 0xbf75bd1cu, 0x57bbebf3u,
            0xea4e70fbu, 0x898d7b97u, 0xe84cdec2u, 0x75e1ee8au,
            0x1674fa29u, 0x7987e026u, 0xa8f36189u, 0xad0bef48u,
            0x99948e58u, 0x522aca48u, 0xe0e86f0du, 0x8a591193u,
            0x1ff7e09au, 0x360aaba5u, 0x33898aa5u, 0x946de2ceu,
            0x4189540cu, 0xecbb2fd0u, 0x682c5bc6u, 0xaef8f072u,
            0x8d435f02u, 0x89e95037u, 0x86af62d7u, 0x5e87d469u,
            0xb127c71bu, 0xb7a83c66u, 0xa9caf024u, 0x9943a9d6u,
            0xe56d7116u, 0x1019969eu, 0xaf6424f0u, 0x3cd9f962u,
            0x19e48be5u, 0xeea03e6du, 0x77769044u, 0x83daad54u,
            0x467c4cfeu, 0xe06ce572u, 0xfff57eeu, 0xaa3690bdu,
            0xe1ce4f9cu, 0xfcb4afc7u, 0x3ab80f36u, 0x53e9e77cu,
            0x258d93au, 0x14cda876u, 0x74556574u, 0xaefc5ef4u,
            0x154c9356u, 0xc17ef3ebu, 0x27a5003du, 0x96868e60u,
            0x7082c235u, 0xec677ceeu, 0x8a1e947au, 0x376dd181u)

        val empty: MHash = MHash(0u)

        fun fromByte(x: Byte): MHash = MHash(table[x.toInt() and 0xFF])

        fun fromShort(x: Short): MHash {
            val x = x.toInt()
            val low = x and 0xFF
            val high = x ushr 8
            return MHash(combineRaw(
                table[low],
                table[high]))
        }

        fun fromChar(x: Char): MHash = fromShort(x.toShort())

        fun fromInt(x: Int): MHash {
            val a0 = x and 0xFF
            val a1 = (x ushr 8) and 0xFF
            val a2 = (x ushr 16) and 0xFF
            val a3 = (x ushr 24) and 0xFF

            val h1 = combineRaw(
                table[a0],
                table[a1])
            val h2 = combineRaw(
                table[a2],
                table[a3])
            return MHash(combineRaw(h1, h2))
        }

        // FIXME: inline
        fun fromLong(x: Long): MHash =
        fromInt(x.toInt()) + fromInt((x ushr 32).toInt())

        fun fromByteArray(array: ByteArray): MHash {
            var r = 0u
            var i = 0
            val length = array.size
            while (i < length) {
                r = combineRaw(r, table[array[i].toInt() and 0xFF])
                i += 1
            }
            return MHash(r)
        }

        private fun combineRaw(x: UInt, y: UInt): UInt {
            val x0 = x shr 16
            val x1 = x and 0xFFFFu
            val x3 = (x1 shl 1) or 1u
            val y0 = y shr 16
            val y1 = y and 0xFFFFu
            val z0 = (x0 + x3 * y0) and 0xFFFFu
            val z1 = (x1 + x3 * y1) and 0xFFFFu
            return (z0 shl 16) or z1
        }
    }
}
