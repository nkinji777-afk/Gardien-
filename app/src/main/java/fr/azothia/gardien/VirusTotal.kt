package fr.azothia.gardien

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Vérification facultative d'une empreinte sur VirusTotal (≈70 moteurs antivirus). Clé API gratuite. */
object VirusTotal {

    class Result(val malicious: Int, val message: String)

    fun lookup(apiKey: String, sha256: String): Result {
        val c = URL("https://www.virustotal.com/api/v3/files/$sha256").openConnection() as HttpURLConnection
        c.connectTimeout = 15000
        c.readTimeout = 20000
        c.setRequestProperty("x-apikey", apiKey)
        try {
            return when (c.responseCode) {
                200 -> {
                    val body = c.inputStream.bufferedReader().use { it.readText() }
                    val stats = JSONObject(body).getJSONObject("data")
                        .getJSONObject("attributes").getJSONObject("last_analysis_stats")
                    val mal = stats.optInt("malicious")
                    val sus = stats.optInt("suspicious")
                    val clean = stats.optInt("undetected") + stats.optInt("harmless")
                    val verdict = when {
                        mal >= 3 -> "⚠ MALVEILLANT"
                        mal + sus > 0 -> "Douteux (peu de moteurs le signalent)"
                        else -> "Sain selon VirusTotal"
                    }
                    Result(mal, "$verdict\n\nMalveillant : $mal\nSuspect : $sus\nRien trouvé : $clean")
                }
                404 -> Result(0, "Fichier inconnu de VirusTotal.\nNi sain ni malveillant connu : prudence si l'appli vient d'un site inconnu.")
                401, 403 -> Result(0, "Clé API refusée. Vérifiez-la.")
                429 -> Result(0, "Quota gratuit atteint (4 vérifications / minute). Réessayez dans 1 minute.")
                else -> Result(0, "Erreur VirusTotal : HTTP ${c.responseCode}")
            }
        } finally {
            c.disconnect()
        }
    }
}
