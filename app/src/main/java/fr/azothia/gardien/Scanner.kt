package fr.azothia.gardien

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ContentResolver
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale

enum class Level { DANGER, SUSPECT, WATCH, OK }

class Finding(
    val pkg: String,
    val label: String,
    val isSystem: Boolean,
    val level: Level,
    val score: Int,
    val reasons: List<String>,
    val isAdmin: Boolean,
    val hasAccessibility: Boolean,
    val sha256: String?
)

class DeviceIssue(val title: String, val detail: String, val serious: Boolean)

class ScanResult(val apps: List<Finding>, val device: List<DeviceIssue>, val scanned: Int)

object Scanner {

    private val TRUSTED_STORES = setOf(
        "com.android.vending",              // Google Play
        "com.sec.android.app.samsungapps",  // Galaxy Store
        "com.huawei.appmarket",
        "com.amazon.venezia",
        "com.xiaomi.market",
        "com.xiaomi.mipicks",
        "com.oppo.market",
        "com.heytap.market",
        "com.bbk.appstore",
        "org.fdroid.fdroid"
    )

    /** Permissions à risque, comptées seulement si elles sont accordées. */
    private val PERMS = mapOf(
        "android.permission.READ_SMS" to Pair(12, "lire vos SMS"),
        "android.permission.RECEIVE_SMS" to Pair(12, "intercepter vos SMS"),
        "android.permission.SEND_SMS" to Pair(10, "envoyer des SMS"),
        "android.permission.READ_CALL_LOG" to Pair(10, "journal d'appels"),
        "android.permission.RECORD_AUDIO" to Pair(5, "micro"),
        "android.permission.CAMERA" to Pair(3, "caméra"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to Pair(10, "position en permanence"),
        "android.permission.ACCESS_FINE_LOCATION" to Pair(3, "position précise"),
        "android.permission.READ_CONTACTS" to Pair(3, "contacts"),
        "android.permission.READ_PHONE_STATE" to Pair(2, "état du téléphone")
    )

    /** Permissions spéciales, comptées dès qu'elles sont demandées. */
    private val DECLARED = mapOf(
        "android.permission.REQUEST_INSTALL_PACKAGES" to Pair(8, "Peut installer d'autres applications"),
        "android.permission.SYSTEM_ALERT_WINDOW" to Pair(6, "Peut s'afficher par-dessus les autres applis"),
        "android.permission.PACKAGE_USAGE_STATS" to Pair(6, "Surveille les applis que vous utilisez")
    )

    private val MIMIC = listOf(
        "system", "système", "service", "update", "mise à jour", "wifi", "wi-fi",
        "sync", "security", "sécurité", "google services", "android"
    )

    private val ROOT_FILES = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk"
    )
    private val ROOT_APPS = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su")

    fun scan(ctx: Context, db: Database, progress: (Int, Int) -> Unit): ScanResult {
        val pm = ctx.packageManager
        val cr = ctx.contentResolver
        val list = installed(pm)
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admins = HashSet<String>()
        dpm.activeAdmins?.forEach { admins.add(it.packageName) }
        val access = componentsToPkgs(secure(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))
        val notif = componentsToPkgs(secure(cr, "enabled_notification_listeners"))

        val out = ArrayList<Finding>()
        for ((idx, pi) in list.withIndex()) {
            progress(idx + 1, list.size)
            val f = try {
                analyse(ctx, pm, pi, db, admins, access, notif)
            } catch (e: Exception) {
                null
            }
            if (f != null) out.add(f)
        }
        out.sortWith(compareBy<Finding>({ it.level.ordinal }, { -it.score }))
        return ScanResult(out, deviceChecks(ctx, pm), list.size)
    }

    @Suppress("DEPRECATION")
    private fun installed(pm: PackageManager): List<PackageInfo> =
        pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES)

    private fun secure(cr: ContentResolver, key: String): String? =
        try { Settings.Secure.getString(cr, key) } catch (e: Exception) { null }

    private fun componentsToPkgs(s: String?): Set<String> {
        val res = HashSet<String>()
        if (s.isNullOrEmpty()) return res
        for (part in s.split(':')) {
            val p = part.substringBefore('/').trim()
            if (p.isNotEmpty()) res.add(p)
        }
        return res
    }

    private fun analyse(
        ctx: Context, pm: PackageManager, pi: PackageInfo, db: Database,
        admins: Set<String>, access: Set<String>, notif: Set<String>
    ): Finding? {
        val pkg: String = pi.packageName ?: return null
        if (pkg == ctx.packageName) return null
        val ai: ApplicationInfo = pi.applicationInfo ?: return null
        val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val label = try { ai.loadLabel(pm).toString() } catch (e: Exception) { pkg }
        val reasons = ArrayList<String>()
        var score = 0
        var known: String? = null

        // 1. Détection par signatures (base Échap)
        val byName = db.packages[pkg]
        if (byName != null) {
            known = byName
            reasons.add("Logiciel espion connu : $byName (nom d'application)")
        }
        for (sha1 in certSha1s(pi)) {
            val n = db.certs[sha1]
            if (n != null) {
                if (known == null) known = n
                reasons.add("Signé par l'éditeur d'un logiciel espion connu : $n")
                break
            }
        }
        var sha256: String? = null
        if (!isSystem) {
            sha256 = try { sha256File(ai.sourceDir) } catch (e: Exception) { null }
            val h = if (sha256 != null) db.hashes[sha256] else null
            if (h != null) {
                if (known == null) known = h
                reasons.add("Fichier identique à un logiciel espion connu : $h")
            }
        }

        // 2. Détection par comportement (heuristique)
        val isAdmin = pkg in admins
        val hasAcc = pkg in access
        if (!isSystem) {
            if (isAdmin) {
                score += 30
                reasons.add("Administrateur de l'appareil : peut bloquer sa désinstallation")
            }
            if (hasAcc) {
                score += 30
                reasons.add("Accessibilité activée : peut lire l'écran et cliquer à votre place")
            }
            if (pkg in notif) {
                score += 15
                reasons.add("Lit toutes vos notifications (messages, codes de validation)")
            }
            val installer = installerOf(pm, pkg)
            val fromStore = installer != null && installer in TRUSTED_STORES
            if (!fromStore) {
                score += 15
                val src = if (installer != null) " ($installer)" else ""
                reasons.add("Installée hors d'un magasin officiel$src")
            }
            if (pm.getLaunchIntentForPackage(pkg) == null) {
                score += 15
                reasons.add("Aucune icône : application cachée")
            }
            val lower = label.lowercase(Locale.ROOT)
            if (!fromStore && MIMIC.any { lower.contains(it) }) {
                score += 15
                reasons.add("Nom qui imite une appli système (« $label »)")
            }
            val req = pi.requestedPermissions
            val flags = pi.requestedPermissionsFlags
            if (req != null) {
                var permScore = 0
                val granted = ArrayList<String>()
                for (i in req.indices) {
                    val p = req[i] ?: continue
                    val ok = flags != null && i < flags.size &&
                        (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    val w = PERMS[p]
                    if (w != null && ok) {
                        permScore += w.first
                        granted.add(w.second)
                    }
                    val d = DECLARED[p]
                    if (d != null) {
                        permScore += d.first
                        reasons.add(d.second)
                    }
                }
                if (granted.isNotEmpty()) reasons.add("Accès accordés : " + granted.distinct().joinToString(", "))
                score += minOf(permScore, 40)
            }
        }

        val level = when {
            known != null -> Level.DANGER
            score >= 60 -> Level.SUSPECT
            score >= 30 -> Level.WATCH
            else -> Level.OK
        }
        if (known != null) score += 100
        return Finding(pkg, label, isSystem, level, score, reasons, isAdmin, hasAcc, sha256)
    }

    private fun certSha1s(pi: PackageInfo): List<String> {
        val si = pi.signingInfo ?: return emptyList()
        val sigs = (if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory)
            ?: return emptyList()
        val res = ArrayList<String>()
        for (s in sigs) {
            if (s == null) continue
            val md = MessageDigest.getInstance("SHA-1")
            res.add(hex(md.digest(s.toByteArray())).uppercase(Locale.ROOT))
        }
        return res
    }

    private fun sha256File(path: String?): String? {
        if (path == null) return null
        val f = File(path)
        if (!f.canRead() || f.length() > 400L * 1024 * 1024) return null
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { ins ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return hex(md.digest())
    }

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    @Suppress("DEPRECATION")
    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else pm.getInstallerPackageName(pkg)
    } catch (e: Exception) {
        null
    }

    private fun deviceChecks(ctx: Context, pm: PackageManager): List<DeviceIssue> {
        val res = ArrayList<DeviceIssue>()
        val cr = ctx.contentResolver

        val rootFile = ROOT_FILES.any { try { File(it).exists() } catch (e: Exception) { false } }
        val rootApp = ROOT_APPS.any { isInstalled(pm, it) }
        if (rootFile || rootApp) {
            res.add(DeviceIssue(
                "Téléphone rooté",
                "Un logiciel malveillant peut se cacher dans le système, hors de portée de toute appli. " +
                    "Si une infection est confirmée : réinitialisation complète recommandée.",
                true
            ))
        }
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) {
            res.add(DeviceIssue("Système non officiel", "Le système n'est pas signé par le fabricant.", true))
        }

        val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!km.isDeviceSecure) {
            res.add(DeviceIssue(
                "Aucun verrouillage d'écran",
                "N'importe qui peut prendre le téléphone et y installer un logiciel espion en 2 minutes. " +
                    "Ajoutez un code dans Paramètres > Sécurité.",
                true
            ))
        }

        val patch = Build.VERSION.SECURITY_PATCH
        try {
            val d = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).parse(patch)
            if (d != null) {
                val days = (System.currentTimeMillis() - d.time) / 86_400_000L
                if (days > 180) {
                    res.add(DeviceIssue(
                        "Mises à jour de sécurité anciennes",
                        "Dernier correctif : $patch (il y a $days jours). Faites les mises à jour système.",
                        days > 365
                    ))
                }
            }
        } catch (e: Exception) {
            // date illisible : on ignore
        }

        val adb = try { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1 } catch (e: Exception) { false }
        if (adb) {
            res.add(DeviceIssue(
                "Débogage USB activé",
                "Permet d'installer des applis depuis un ordinateur. Désactivez-le si vous ne l'utilisez pas " +
                    "(Paramètres > Options pour les développeurs).",
                false
            ))
        }
        return res
    }

    private fun isInstalled(pm: PackageManager, pkg: String): Boolean = try {
        @Suppress("DEPRECATION")
        pm.getPackageInfo(pkg, 0)
        true
    } catch (e: Exception) {
        false
    }
}
