package de.wuefl.wkeepass.sicherheit

import android.app.Activity
import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import de.wuefl.wkeepass.R
import de.wuefl.wkeepass.kern.Kern
import org.json.JSONObject

/**
 * Das Blatt, das nach dem Schlüssel fragt — im Dienst, nicht in der App.
 *
 * Zwei Fragen, dieselbe Form:
 *
 * ```text
 * entsperren   Die Datenbank ist zu. Biometrie, PIN oder Master-Passwort
 *              öffnen sie hier, ohne dass man in die App wechseln muss.
 * nachweis     Die Datenbank ist offen, aber vor dem Einsetzen soll
 *              feststehen, dass du es bist (Einstellung „Vor dem Ausfüllen").
 * ```
 *
 * Geprüft wird beides im Kern (`android_services.rs`) — hier steht nur der
 * Dialog. Die Biometrie ist der einzige Unterschied zwischen beiden Fällen:
 * Beim Entsperren rechnet der Sicherheitschip einen Schlüssel, ohne den das
 * Master-Passwort versiegelt bliebe; beim Nachweis genügt die Antwort des
 * Systemdialogs, denn die Datenbank ist ja schon offen.
 *
 * Kein Aufruf in den Kern läuft auf dem Hauptfaden: Entsperren heißt Argon2,
 * und das dauert (siehe [Kern.imHintergrund]).
 */
object Nachweisblatt {

    /** Öffnet die Datenbank. `weiter(true)`: Sie ist jetzt offen. */
    fun entsperren(activity: Activity, weiter: (Boolean) -> Unit) {
        Kern.imHintergrund({ Kern.wege() }) { wege ->
            // Keine Datenbank ausgewählt: Hier ist nichts zu öffnen, also
            // doch der Weg über die App.
            if (wege.has("fehler")) {
                Kern.appOeffnen(activity)
                return@imHintergrund weiter(false)
            }
            blatt(
                activity = activity,
                titel = "WKeePass entsperren",
                unten = wege.optString("name").ifEmpty { "Deine Datenbank" },
                knopf = "Entsperren",
                biometrie = if (wege.optBoolean("geraet")) {
                    "Mit ${wege.optString("geraetName").ifEmpty { "Biometrie" }} entsperren"
                } else {
                    null
                },
                pin = wege.optBoolean("pin"),
                // Der Systemdialog gibt hier den Schlüssel frei — das macht
                // der Kern, nicht diese Klasse.
                biometrieSelbst = false,
                pruefe = { methode, geheimnis -> Kern.entsperren(methode, geheimnis) },
                weiter = weiter,
            )
        }
    }

    /**
     * Fragt vor dem Einsetzen. `stufe` ist die Einstellung `android.guard`:
     * `confirm` will nur einen Knopfdruck, `identify` einen Schlüssel.
     */
    fun nachweis(activity: Activity, stufe: String, ziel: String, weiter: (Boolean) -> Unit) {
        if (stufe == "confirm") {
            return blatt(
                activity = activity,
                titel = "Zugang einsetzen?",
                unten = ziel,
                knopf = "Einsetzen",
                biometrie = null,
                pin = false,
                biometrieSelbst = false,
                feld = false,
                pruefe = { _, _ -> Kern.pruefen("bestaetigt", "") },
                weiter = weiter,
            )
        }

        Kern.imHintergrund({ Kern.wege() }) { wege ->
            blatt(
                activity = activity,
                titel = "Bist du es?",
                unten = ziel,
                knopf = "Bestätigen",
                biometrie = "Mit Biometrie bestätigen",
                pin = wege.optBoolean("pinGesetzt"),
                biometrieSelbst = true,
                pruefe = { methode, geheimnis -> Kern.pruefen(methode, geheimnis) },
                weiter = weiter,
            )
        }
    }

    /**
     * Baut das Blatt und führt die Prüfung aus.
     *
     * `biometrieSelbst`: Den Systemdialog zeigt [Bestaetigung], und erst
     * seine Antwort geht als `bestaetigt` an den Kern. Sonst übernimmt der
     * Kern die Prüfung selbst — er braucht den Schlüssel, nicht das Ja.
     */
    private fun blatt(
        activity: Activity,
        titel: String,
        unten: String,
        knopf: String,
        biometrie: String?,
        pin: Boolean,
        biometrieSelbst: Boolean,
        feld: Boolean = true,
        pruefe: (String, String) -> String,
        weiter: (Boolean) -> Unit,
    ) {
        if (activity.isFinishing || activity.isDestroyed) return weiter(false)

        val blatt = Dialog(activity)
        blatt.setContentView(R.layout.wkeepass_nachweis)
        blatt.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setGravity(Gravity.BOTTOM)
            setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }

        blatt.findViewById<TextView>(R.id.wkeepass_nachweis_titel).text = titel
        blatt.findViewById<TextView>(R.id.wkeepass_nachweis_unten).text = unten

        val bioKnopf = blatt.findViewById<Button>(R.id.wkeepass_nachweis_biometrie)
        val wege = blatt.findViewById<View>(R.id.wkeepass_nachweis_wege)
        val pinKnopf = blatt.findViewById<Button>(R.id.wkeepass_nachweis_pin)
        val masterKnopf = blatt.findViewById<Button>(R.id.wkeepass_nachweis_master)
        val eingabe = blatt.findViewById<EditText>(R.id.wkeepass_nachweis_feld)
        val weiterKnopf = blatt.findViewById<Button>(R.id.wkeepass_nachweis_weiter)
        val meldung = blatt.findViewById<TextView>(R.id.wkeepass_nachweis_meldung)

        weiterKnopf.text = knopf
        bioKnopf.text = biometrie ?: ""
        bioKnopf.visibility = if (biometrie == null) View.GONE else View.VISIBLE
        wege.visibility = if (feld && pin) View.VISIBLE else View.GONE
        eingabe.visibility = if (feld) View.VISIBLE else View.GONE

        // Ohne PIN bleibt nur das Master-Passwort; mit PIN fängt es damit an,
        // sie ist der kürzere Weg.
        var methode = if (feld && pin) "pin" else "master"
        fun waehle(neu: String) {
            methode = neu
            pinKnopf.alpha = if (neu == "pin") 1f else 0.55f
            masterKnopf.alpha = if (neu == "master") 1f else 0.55f
            eingabe.hint = if (neu == "pin") "PIN" else "Master-Passwort"
            eingabe.inputType = if (neu == "pin") {
                InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            } else {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
        }
        waehle(methode)

        pinKnopf.setOnClickListener { waehle("pin") }
        masterKnopf.setOnClickListener { waehle("master") }

        // Abbrechen ist eine gültige Antwort — nur eben ein Nein. `fertig`
        // sorgt dafür, dass genau eine Antwort herausgeht.
        var beantwortet = false
        fun fertig(ok: Boolean) {
            if (beantwortet) return
            beantwortet = true
            blatt.setOnDismissListener(null)
            if (blatt.isShowing) blatt.dismiss()
            weiter(ok)
        }

        fun arbeite(aufruf: () -> String) {
            weiterKnopf.isEnabled = false
            bioKnopf.isEnabled = false
            meldung.visibility = View.GONE
            Kern.imHintergrund(aufruf) { antwort ->
                weiterKnopf.isEnabled = true
                bioKnopf.isEnabled = true
                val fehler = fehlertext(antwort)
                if (fehler == null) return@imHintergrund fertig(true)
                eingabe.text.clear()
                meldung.text = fehler
                meldung.visibility = View.VISIBLE
            }
        }

        weiterKnopf.setOnClickListener {
            val geheimnis = if (feld) eingabe.text.toString() else ""
            if (feld && geheimnis.isEmpty()) return@setOnClickListener
            arbeite { pruefe(methode, geheimnis) }
        }

        bioKnopf.setOnClickListener {
            if (!biometrieSelbst) return@setOnClickListener arbeite { pruefe("geraet", "") }
            Bestaetigung.fragen(activity, titel) { ok ->
                if (ok) arbeite { pruefe("bestaetigt", "") }
            }
        }

        blatt.setOnDismissListener { fertig(false) }
        blatt.show()
    }

    /** Der Grund, warum es nicht geklappt hat — oder `null`, wenn doch. */
    private fun fehlertext(antwort: JSONObject): String? = when {
        antwort.has("fehler") -> antwort.optString("fehler")
        Kern.gesperrt(antwort) -> "Die Datenbank ist zu."
        else -> null
    }
}
