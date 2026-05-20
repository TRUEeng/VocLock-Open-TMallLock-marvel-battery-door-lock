package com.voc.lock

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object Crypto {

    fun hexToBytes(hex: String): ByteArray {
        val s = hex.replace(" ", "").replace(":", "")
        return ByteArray(s.length / 2) {
            s.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }

    fun crc8(hexStr: String): String {
        val s = hexStr.replace(" ", "")
        var total = 0
        for (i in s.indices step 2) {
            total += s.substring(i, i + 2).toInt(16)
        }
        return "%02X".format(total and 0xFF)
    }

    fun xorKey(randomHex: String, activationKeyHex: String): String {
        val r = randomHex.uppercase()
        val k = activationKeyHex.uppercase()
        return buildString {
            for (i in 0 until 32 step 2) {
                val xor = r.substring(i, i + 2).toInt(16) xor
                        k.substring(i, i + 2).toInt(16)
                append("%02X".format(xor))
            }
        }
    }

    fun aesEncrypt(plaintextHex: String, keyHex: String): String {
        val key    = hexToBytes(keyHex).copyOf(16)
        val data   = hexToBytes(plaintextHex)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return bytesToHex(cipher.doFinal(data))
    }

    fun aesDecrypt(ciphertextHex: String, keyHex: String): String {
        val key    = hexToBytes(keyHex).copyOf(16)
        val data   = hexToBytes(ciphertextHex)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return bytesToHex(cipher.doFinal(data))
    }

    fun buildUnlockPacket(randomHex: String, activationKeyHex: String): String {
        val sessionKey = xorKey(randomHex, activationKeyHex)
        val cmdContent = "FF0B0000"
        val crc        = crc8("55AA$cmdContent")
        val plaintext  = (cmdContent + crc).padEnd(32, '0')
        val ciphertext = aesEncrypt(plaintext, sessionKey)
        val length     = "%04X".format(ciphertext.length / 2)
        val packet     = "55AA$length$ciphertext"
        return (packet + crc8(packet)).uppercase()
    }
}
