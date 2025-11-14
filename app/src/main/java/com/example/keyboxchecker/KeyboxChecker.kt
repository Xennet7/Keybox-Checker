package com.example.keyboxchecker

import android.content.Context
import android.net.Uri
import android.util.Xml
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.xmlpull.v1.XmlPullParser
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.*

object KeyboxChecker {

    data class CertInfo(
        val cert: X509Certificate,
        val subject: String,
        val issuer: String,
        val notBefore: Date,
        val notAfter: Date,
        val serialHex: String,
        val sha256Fingerprint: String,
        var revoked: Boolean = false,
        var comparedHex: String = ""
    )

    private val httpClient = OkHttpClient()

    private fun hexToBytes(hex: String): ByteArray {
        val cleaned = hex.replace("\\s".toRegex(), "").replace(":", "")
        val len = cleaned.length
        val data = ByteArray((len + 1) / 2)
        var src = 0
        var dst = 0
        if (len % 2 == 1) {
            data[dst++] = cleaned.substring(0,1).toInt(16).toByte()
            src = 1
        }
        while (src < len) {
            data[dst++] = cleaned.substring(src, src+2).toInt(16).toByte()
            src += 2
        }
        return data.sliceArray(0 until dst)
    }

    private fun base64ToBytes(b64: String): ByteArray =
        android.util.Base64.decode(b64.replace("\\s".toRegex(), ""), android.util.Base64.DEFAULT)

    private fun sha256Hex(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString(":") { String.format("%02X", it) }
    }

    private fun canonicalSerialHex(bi: BigInteger): String {
        val hex = bi.toString(16).uppercase(Locale.ROOT)
        return hex.trimStart('0').ifEmpty { "0" }
    }

    fun parseKeybox(input: InputStream): List<CertInfo> {
        val parser: XmlPullParser = Xml.newPullParser()
        parser.setInput(input, null)
        val cf = CertificateFactory.getInstance("X.509")
        val list = mutableListOf<CertInfo>()
        var event = parser.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG) {
                val name = parser.name?.lowercase(Locale.ROOT) ?: ""
                if (name.contains("cert")) {
                    val text = try { parser.nextText().trim() } catch (t: Exception) { "" }
                    if (text.isEmpty()) { event = parser.next(); continue }
                    val bytes = when {
                        text.contains("-----BEGIN CERTIFICATE-----") -> {
                            val b64 = text.replace("-----BEGIN CERTIFICATE-----", "")
                                .replace("-----END CERTIFICATE-----", "")
                                .replace("\\s".toRegex(), "")
                            base64ToBytes(b64)
                        }
                        text.matches(Regex("^[0-9A-Fa-f\\s:]+")) -> hexToBytes(text)
                        else -> try { base64ToBytes(text) } catch (e: Exception) { null }
                    }
                    if (bytes != null) {
                        try {
                            val cert = cf.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
                            val serial = canonicalSerialHex(cert.serialNumber)
                            val sha = sha256Hex(cert.encoded)
                            val info = CertInfo(
                                cert = cert,
                                subject = cert.subjectX500Principal.name,
                                issuer = cert.issuerX500Principal.name,
                                notBefore = cert.notBefore,
                                notAfter = cert.notAfter,
                                serialHex = serial,
                                sha256Fingerprint = sha
                            )
                            list.add(info)
                        } catch (e: Exception) {
                            // skip invalid
                        }
                    }
                }
            }
            event = parser.next()
        }
        return list
    }

    suspend fun checkRevocations(context: Context, uri: Uri): Pair<List<CertInfo>, Boolean> =
        withContext(Dispatchers.IO) {
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IllegalArgumentException("Cannot open file")
            val certs = parseKeybox(input)
            val revokedSet = try { fetchGoogleRevoked() } catch (e: Exception) { emptySet<String>() }

            var anyRevoked = false
            for (c in certs) {
                val compared = c.serialHex.uppercase(Locale.ROOT).trimStart('0').ifEmpty { "0" }
                c.comparedHex = compared
                if (revokedSet.contains(compared)) {
                    c.revoked = true
                    anyRevoked = true
                } else {
                    c.revoked = false
                }
            }
            return@withContext Pair(certs, !anyRevoked)
        }

    private suspend fun fetchGoogleRevoked(): Set<String> = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url("https://android.googleapis.com/attestation/status")
            .get()
            .build()
        httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@withContext emptySet()
            val body = resp.body?.string() ?: return@withContext emptySet()
            val gson = Gson()
            val parsed = gson.fromJson(body, Any::class.java)
            val set = mutableSetOf<String>()
            if (parsed is List<*>) {
                for (it in parsed) {
                    when (it) {
                        is String -> set.add(it.uppercase(Locale.ROOT).trimStart('0').ifEmpty { "0" })
                        is Map<*,*> -> {
                            val cand = it["serial"] ?: it["serialNumber"] ?: it["serial_number"]
                            if (cand is String) set.add(cand.uppercase(Locale.ROOT).trimStart('0').ifEmpty { "0" })
                        }
                    }
                }
            } else if (parsed is Map<*,*>) {
                for ((_, v) in parsed) {
                    if (v is List<*>) {
                        for (it in v) if (it is String) set.add(it.uppercase(Locale.ROOT).trimStart('0').ifEmpty { "0" })
                    }
                }
            }
            return@withContext set
        }
    }
}
