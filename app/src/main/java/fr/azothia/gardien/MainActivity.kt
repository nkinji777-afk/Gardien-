package fr.azothia.gardien

import android.app.Activity
import android.app.AlertDialog
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var db: Database
    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private lateinit var scanBtn: Button
    private val main = Handler(Looper.getMainLooper())
    private var scanning = false
    private var scannedOnce = false
    private var report = ""

    private val red = Color.parseColor("#FDECEA")
    private val orange = Color.parseColor("#FFF4E0")
    private val yellow = Color.parseColor("#FFFBE6")
    private val green = Color.parseColor("#E8F5E9")
    private val grey = Color.parseColor("#F2F4F7")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = Database(this)
        try { db.load() } catch (e: Exception) { toast("Base illisible : ${e.message}") }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(24), dp(16), dp(32))
        }
        root.addView(text("🛡 Gardien", 26f, bold = true))
        root.addView(text("Détecte et supprime les logiciels espions et malveillants.", 14f).apply {
            setTextColor(Color.DKGRAY)
        })
        status = text(db.summary(), 13f).apply { setPadding(0, dp(8), 0, dp(8)); setTextColor(Color.GRAY) }
        root.addView(status)

        scanBtn = button("Analyser le téléphone") { startScan() }
        root.addView(scanBtn)
        root.addView(button("Mettre à jour la base") { updateDb() })
        root.addView(button("Clé VirusTotal (facultatif)") { askKey(null) })

        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(content)

        root.addView(text(
            "Base de détection : association Échap (stalkerware-indicators, licence CC-BY 4.0).",
            11f
        ).apply { setTextColor(Color.GRAY); setPadding(0, dp(24), 0, 0) })

        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        // Après une désinstallation ou un réglage, on relance l'analyse pour vérifier.
        if (scannedOnce && !scanning) startScan()
    }

    // ---------- Analyse ----------

    private fun startScan() {
        if (scanning) return
        scanning = true
        scanBtn.isEnabled = false
        content.removeAllViews()
        status.text = "Analyse en cours…"
        thread {
            val r = try {
                Scanner.scan(this, db) { i, n ->
                    if (i % 15 == 0 || i == n) main.post { status.text = "Analyse… $i / $n applications" }
                }
            } catch (e: Exception) {
                null
            }
            main.post {
                scanning = false
                scannedOnce = true
                scanBtn.isEnabled = true
                if (r == null) status.text = "Erreur pendant l'analyse." else show(r)
            }
        }
    }

    private fun show(r: ScanResult) {
        content.removeAllViews()
        val danger = r.apps.filter { it.level == Level.DANGER }
        val suspect = r.apps.filter { it.level == Level.SUSPECT }
        val watch = r.apps.filter { it.level == Level.WATCH }
        val okCount = r.apps.count { it.level == Level.OK }
        val seriousDevice = r.device.any { it.serious }
        status.text = "${r.scanned} applications analysées · " + db.summary()

        val (title, color) = when {
            danger.isNotEmpty() -> Pair("⚠ Infection détectée (${danger.size})", red)
            suspect.isNotEmpty() -> Pair("Applications suspectes (${suspect.size})", orange)
            seriousDevice -> Pair("Aucune infection connue, mais téléphone vulnérable", orange)
            else -> Pair("✅ Aucune infection détectée", green)
        }
        val head = card(color)
        head.addView(text(title, 20f, bold = true))
        content.addView(head)

        val sb = StringBuilder("Rapport Gardien\n$title\n${r.scanned} applications analysées\n\n")

        if (danger.isNotEmpty()) {
            val warn = card(yellow)
            warn.addView(text("Avant de supprimer", 16f, bold = true))
            warn.addView(text(
                "Un logiciel espion est souvent installé par un proche. Le supprimer peut l'alerter.\n" +
                    "• Faites une capture d'écran de ce rapport (preuve).\n" +
                    "• En danger ? Appelez le 3919 (gratuit, anonyme) ou le 17.\n" +
                    "• Changez ensuite vos mots de passe depuis un autre appareil.",
                14f
            ))
            content.addView(warn)
        }

        if (r.device.isNotEmpty()) {
            content.addView(section("Sécurité du téléphone"))
            for (d in r.device) {
                val c = card(if (d.serious) orange else grey)
                c.addView(text(d.title, 16f, bold = true))
                c.addView(text(d.detail, 14f))
                content.addView(c)
                sb.append("[Téléphone] ${d.title} : ${d.detail}\n")
            }
        }
        addGroup("Infections", danger, red, sb)
        addGroup("Suspectes", suspect, orange, sb)
        addGroup("À surveiller", watch, yellow, sb)

        content.addView(text("$okCount applications sans signe de problème.", 13f).apply {
            setTextColor(Color.GRAY); setPadding(0, dp(12), 0, dp(4))
        })
        report = sb.toString()
        content.addView(button("Partager le rapport") { shareReport() })
    }

    private fun addGroup(name: String, list: List<Finding>, color: Int, sb: StringBuilder) {
        if (list.isEmpty()) return
        content.addView(section(name))
        for (f in list) {
            content.addView(appCard(f, color))
            sb.append("[$name] ${f.label} (${f.pkg})\n")
            for (r in f.reasons) sb.append("  - $r\n")
        }
    }

    private fun appCard(f: Finding, color: Int): View {
        val c = card(color)
        c.addView(text(f.label, 17f, bold = true))
        val sys = if (f.isSystem) " · appli système" else ""
        c.addView(text(f.pkg + sys, 12f).apply { setTextColor(Color.GRAY) })
        for (r in f.reasons) c.addView(text("• $r", 14f))

        var step = 1
        if (f.isAdmin) c.addView(button("${step++}. Retirer les droits administrateur") { openAdminSettings(f) })
        if (f.hasAccessibility) {
            c.addView(button("${step++}. Couper l'accessibilité") {
                toast("Désactivez « ${f.label} »")
                open(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            })
        }
        if (!f.isSystem) {
            c.addView(button("${step++}. Supprimer l'application") { uninstall(f) })
        } else {
            c.addView(button("${step++}. Désactiver (appli système)") { openDetails(f.pkg) })
        }
        c.addView(button("Détails / forcer l'arrêt") { openDetails(f.pkg) })
        if (f.sha256 != null) c.addView(button("Vérifier sur VirusTotal") { vtCheck(f) })
        return c
    }

    // ---------- Suppression ----------

    private fun uninstall(f: Finding) {
        if (isStillAdmin(f.pkg)) {
            toast("Retirez d'abord ses droits administrateur, sinon la suppression sera bloquée.")
            openAdminSettings(f)
            return
        }
        open(Intent(Intent.ACTION_DELETE, Uri.fromParts("package", f.pkg, null)))
    }

    private fun isStillAdmin(pkg: String): Boolean {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        return dpm.activeAdmins?.any { it.packageName == pkg } == true
    }

    private fun openAdminSettings(f: Finding) {
        toast("Décochez « ${f.label} »")
        val tries = listOf(
            Intent().setClassName("com.android.settings", "com.android.settings.DeviceAdminSettings"),
            Intent().setClassName(
                "com.android.settings",
                "com.android.settings.Settings\$DeviceAdminSettingsActivity"
            ),
            Intent(Settings.ACTION_SECURITY_SETTINGS)
        )
        for (i in tries) {
            try {
                startActivity(i)
                return
            } catch (e: Exception) {
                // on essaie l'écran suivant
            }
        }
        toast("Ouvrez Paramètres > Sécurité > Applis d'administration")
    }

    private fun openDetails(pkg: String) =
        open(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", pkg, null)))

    private fun open(i: Intent) {
        try {
            startActivity(i)
        } catch (e: Exception) {
            toast("Impossible d'ouvrir cet écran sur ce téléphone.")
        }
    }

    // ---------- Base & VirusTotal ----------

    private fun updateDb() {
        status.text = "Téléchargement de la base…"
        thread {
            val msg = try { db.update() } catch (e: Exception) { "Échec de la mise à jour : ${e.message}" }
            main.post { status.text = msg; toast(msg) }
        }
    }

    private fun vtCheck(f: Finding) {
        val key = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_VT, null)
        if (key.isNullOrBlank()) {
            askKey(f)
            return
        }
        val sha = f.sha256 ?: return
        toast("Vérification de « ${f.label} »…")
        thread {
            val msg = try { VirusTotal.lookup(key, sha).message } catch (e: Exception) { "Erreur réseau : ${e.message}" }
            main.post {
                if (!isFinishing) {
                    AlertDialog.Builder(this).setTitle(f.label).setMessage(msg)
                        .setPositiveButton("OK", null).show()
                }
            }
        }
    }

    private fun askKey(then: Finding?) {
        val input = EditText(this).apply {
            hint = "Collez votre clé API"
            setText(getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_VT, ""))
        }
        AlertDialog.Builder(this)
            .setTitle("Clé VirusTotal")
            .setMessage("Gratuite : créez un compte sur virustotal.com, puis copiez « API key ». Elle permet de croiser une appli avec ~70 antivirus.")
            .setView(input)
            .setPositiveButton("Enregistrer") { _, _ ->
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString(KEY_VT, input.text.toString().trim()).apply()
                if (then != null) vtCheck(then)
            }
            .setNegativeButton("Annuler", null)
            .show()
    }

    private fun shareReport() {
        val i = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, report)
        }
        open(Intent.createChooser(i, "Partager le rapport"))
    }

    // ---------- Petits outils d'interface ----------

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun text(s: String, size: Float, bold: Boolean = false): TextView = TextView(this).apply {
        text = s
        textSize = size
        setTextColor(Color.parseColor("#1A1A1A"))
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(2), 0, dp(2))
    }

    private fun section(s: String): TextView = text(s, 18f, bold = true).apply { setPadding(0, dp(18), 0, dp(4)) }

    private fun button(label: String, action: () -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        gravity = Gravity.CENTER
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(4) }
    }

    private fun card(color: Int): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(14), dp(12), dp(14), dp(12))
        background = GradientDrawable().apply {
            setColor(color)
            cornerRadius = dp(12).toFloat()
        }
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = dp(10) }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    companion object {
        private const val PREFS = "gardien"
        private const val KEY_VT = "vt_key"
    }
}
