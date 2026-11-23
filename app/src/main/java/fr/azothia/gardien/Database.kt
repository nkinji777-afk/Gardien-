package fr.azothia.gardien

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Base de logiciels espions connus.
 * Source : association Échap — github.com/AssoEchap/stalkerware-indicators (licence CC-BY 4.0).
 * Fichiers au format « valeur|nom de la famille ».
 */
class Database(private val ctx: Context) {
    val packages = HashMap<String, String>()
    val certs = HashMap<String, String>()
    val hashes = HashMap<String, String>()

    fun load() {
        packages.clear(); certs.clear(); hashes.clear()
        read(FILE_PACKAGES, packages)
        read(FILE_CERTS, certs)
        read(FILE_HASHES, hashes)
    }

    fun summary(): String =
        "${packages.size} applis espionnes, ${certs.size} signatures, ${hashes.size} empreintes connues"

    private fun read(name: String, into: MutableMap<String, String>) {
        val local = File(ctx.filesDir, name)
        val lines = if (local.exists()) {
            local.readLines()
        } else {
            ctx.assets.open(name).bufferedReader().use { it.readLines() }
        }
        for (l in lines) {
            val i = l.indexOf('|')
            if (i > 0) into[l.substring(0, i)] = l.substring(i + 1)
        }
    }

    /** Télécharge la dernière version de la base. À appeler hors du fil principal. */
    fun update(): String {
        val yaml = download(BASE + "ioc.yaml")
        val csv = download(BASE + "samples.csv")
        val pk = HashMap<String, String>()
        val ce = HashMap<String, String>()
        val hs = HashMap<String, String>()

        var name = ""
        var section = ""
        var nested = false
        for (line in yaml.lines()) {
            if (line.startsWith("- name:")) {
                name = clean(line.substringAfter(":"))
                section = ""
                nested = false
                continue
            }
            val t = line.trimStart()
            val indent = line.length - t.length
            if (indent >= 2 && t.startsWith("- ")) {
                val v = clean(t.substring(2))
                if (v.isNotEmpty() && !nested) {
                    if (section == "packages") pk[v] = name
                    if (section == "certificates") ce[v.uppercase()] = name
                }
                continue
            }
            if (t.contains(":")) {
                if (indent == 2) {
                    section = t.substringBefore(":")
                    nested = false
                } else if (indent > 2) {
                    nested = true
                }
            }
        }

        for (line in csv.lines().drop(1)) {
            val c = line.split(",")
            if (c.size < 5) continue
            val app = clean(c.subList(4, c.size).joinToString(","))
            val sha = c[0].trim().lowercase()
            val pkg = c[1].trim()
            val cert = c[2].trim().uppercase()
            if (sha.length == 64) hs[sha] = app
            if (pkg.isNotEmpty() && !pk.containsKey(pkg)) pk[pkg] = app
            if (cert.isNotEmpty() && !ce.containsKey(cert)) ce[cert] = app
        }

        if (pk.isEmpty() || hs.isEmpty()) throw IllegalStateException("base téléchargée vide")

        write(FILE_PACKAGES, pk)
        write(FILE_CERTS, ce)
        write(FILE_HASHES, hs)
        load()
        return "Base à jour : " + summary()
    }

    private fun write(name: String, data: Map<String, String>) {
        val text = data.entries.joinToString("\n") { it.key + "|" + it.value }
        File(ctx.filesDir, name).writeText(text + "\n")
    }

    private fun clean(s: String): String = s.trim().trim('\'', '"').replace("|", " ")

    companion object {
        const val BASE = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
        private const val FILE_PACKAGES = "packages.txt"
        private const val FILE_CERTS = "certs.txt"
        private const val FILE_HASHES = "hashes.txt"

        fun download(url: String): String {
            val c = URL(url).openConnection() as HttpURLConnection
            c.connectTimeout = 15000
            c.readTimeout = 30000
            try {
                if (c.responseCode != 200) throw IllegalStateException("HTTP " + c.responseCode)
                return c.inputStream.bufferedReader().use { it.readText() }
            } finally {
                c.disconnect()
            }
        }
    }
}
