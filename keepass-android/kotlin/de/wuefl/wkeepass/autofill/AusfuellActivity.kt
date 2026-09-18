package de.wuefl.wkeepass.autofill

import android.app.Activity
import android.app.Dialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.service.autofill.Dataset
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ListView
import android.widget.RemoteViews
import android.widget.TextView
import android.widget.Toast
import de.wuefl.wkeepass.R
import de.wuefl.wkeepass.kern.Kern
import org.json.JSONObject

/**
 * Hier entsteht das, was tatsächlich in die fremde App geht.
 *
 * Der Dienst hat vorher nur Zeilen geliefert — mit Kontonamen, aber ohne
 * Passwort; die anfragende App hat nichts gesehen. Tippt der Nutzer eine an,
 * startet Android **diese** Activity, durchsichtig über der fremden App:
 *
 *   * Zeile mit Konto → sofort einsetzen, keine Rückfrage.
 *   * „Anderen Eintrag wählen …" → die Auswahlliste mit Suche. Ein Eintrag,
 *     der noch nicht zur Seite passte, merkt sich dabei die App bzw. Seite.
 *   * Datenbank zu → die App nach vorn holen, damit der Nutzer entsperrt.
 *
 * Hat der Eintrag einen TOTP-Schlüssel, geht der Code ins Code-Feld, falls
 * das Formular eins hat — sonst in die Zwischenablage, für die nächste Seite.
 *
 * `RESULT_CANCELED` heißt: nichts einsetzen. Das ist auch die richtige
 * Antwort bei Abbruch — ein Fehler ist es nicht.
 */
class AusfuellActivity : Activity() {

    private var benutzerId: AutofillId? = null
    private var passwortId: AutofillId? = null
    private var codeId: AutofillId? = null
    private var paket = ""
    private var web = ""

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)

        paket = intent.getStringExtra(WKeePassAutofillService.EXTRA_PAKET) ?: ""
        web = intent.getStringExtra(WKeePassAutofillService.EXTRA_WEB) ?: ""
        benutzerId = feldId(WKeePassAutofillService.EXTRA_BENUTZER_ID)
        passwortId = feldId(WKeePassAutofillService.EXTRA_PASSWORT_ID)
        codeId = feldId(WKeePassAutofillService.EXTRA_CODE_ID)

        if (Kern.gesperrt(Kern.frage { Kern.status() })) {
            Kern.appOeffnen(this)
            return abbrechen()
        }

        // Konto schon in der Zeile gewählt: direkt einsetzen.
        intent.getStringExtra(WKeePassAutofillService.EXTRA_EINTRAG)?.let {
            return einsetzen(it, merken = false)
        }

        val antwort = Kern.frage { Kern.treffer(paket, web) }
        if (antwort.has("fehler")) return fehler(antwort.optString("fehler"))
        val liste = antwort.optJSONArray("eintraege")
        val eintraege = (0 until (liste?.length() ?: 0)).map { liste!!.getJSONObject(it) }
        if (eintraege.isEmpty()) return fehler("In der Datenbank gibt es keine Einträge mit Passwort.")

        auswahl(eintraege)
    }

    /* ---------- Die Auswahlliste ---------- */

    /**
     * Ein Blatt von unten, in den Farben der App: Kopf mit Ziel, Suche,
     * Einträge. Passende stehen oben und tragen die Marke „passt".
     */
    private fun auswahl(alle: List<JSONObject>) {
        val blatt = Dialog(this)
        blatt.setContentView(R.layout.wkeepass_auswahl)
        blatt.window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setGravity(Gravity.BOTTOM)
            setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            // Die Tastatur erst auf Wunsch — meist genügt ein Tipp in die Liste.
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        }

        blatt.findViewById<TextView>(R.id.wkeepass_ziel).text =
            web.ifEmpty { paket }.ifEmpty { "Anmeldung" }

        val adapter = EintragsListe(alle)
        val listview = blatt.findViewById<ListView>(R.id.wkeepass_liste)
        listview.adapter = adapter
        // Höchstens gut die halbe Bildschirmhöhe, damit man sieht, wo man ist.
        listview.layoutParams.height = minOf(
            (alle.size * 66 * resources.displayMetrics.density).toInt(),
            (resources.displayMetrics.heightPixels * 0.55).toInt(),
        )
        listview.setOnItemClickListener { _, _, position, _ ->
            val eintrag = adapter.getItem(position)
            blatt.setOnDismissListener(null)
            blatt.dismiss()
            einsetzen(eintrag.optString("id"), merken = !eintrag.optBoolean("passend"))
        }

        blatt.findViewById<EditText>(R.id.wkeepass_suche).addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = adapter.filtern(s?.toString().orEmpty())
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })

        blatt.setOnDismissListener { abbrechen() }
        blatt.show()
    }

    private inner class EintragsListe(private val alle: List<JSONObject>) : BaseAdapter() {
        private var sichtbar = alle

        fun filtern(text: String) {
            val t = text.trim().lowercase()
            sichtbar = if (t.isEmpty()) alle else alle.filter {
                listOf("titel", "benutzer", "ordner").any { k -> it.optString(k).lowercase().contains(t) }
            }
            notifyDataSetChanged()
        }

        override fun getCount() = sichtbar.size
        override fun getItem(position: Int) = sichtbar[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, alt: View?, eltern: ViewGroup): View {
            val zeile = alt ?: layoutInflater.inflate(R.layout.wkeepass_zeile, eltern, false)
            val e = sichtbar[position]
            val titel = e.optString("titel").ifEmpty { "(ohne Titel)" }
            zeile.findViewById<TextView>(R.id.wkeepass_buchstabe).text = titel.take(1).uppercase()
            zeile.findViewById<TextView>(R.id.wkeepass_zeile_titel).text = titel
            zeile.findViewById<TextView>(R.id.wkeepass_zeile_unten).text =
                listOf(e.optString("benutzer"), e.optString("ordner")).filter { it.isNotEmpty() }.joinToString("  ·  ")
            zeile.findViewById<TextView>(R.id.wkeepass_zeile_marke).text =
                listOfNotNull(
                    "passt".takeIf { e.optBoolean("passend") },
                    "TOTP".takeIf { e.optBoolean("totp") },
                ).joinToString(" · ")
            return zeile
        }
    }

    /* ---------- Einsetzen ---------- */

    private fun einsetzen(id: String, merken: Boolean) {
        val zugang = Kern.frage { Kern.zugang(id, paket, merken) }
        if (Kern.gesperrt(zugang)) {
            Kern.appOeffnen(this)
            return abbrechen()
        }
        if (zugang.has("fehler")) return fehler(zugang.optString("fehler"))

        val benutzer = zugang.optString("benutzer")
        val passwort = zugang.optString("passwort")
        val code = zugang.optString("totp")

        val anzeige = RemoteViews(packageName, R.layout.wkeepass_vorschlag).apply {
            setTextViewText(R.id.wkeepass_oben, benutzer.ifEmpty { "WKeePass" })
            setTextViewText(R.id.wkeepass_unten, "WKeePass")
        }
        @Suppress("DEPRECATION")
        val bau = Dataset.Builder(anzeige)

        // Die Werte gehen an genau die Felder, die der Dienst benannt hat.
        var gesetzt = false
        @Suppress("DEPRECATION")
        fun setze(feld: AutofillId?, wert: String) {
            if (feld != null && wert.isNotEmpty()) {
                bau.setValue(feld, AutofillValue.forText(wert))
                gesetzt = true
            }
        }
        setze(benutzerId, benutzer)
        setze(passwortId, passwort)
        setze(codeId, code)

        // Kein Code-Feld hier, aber ein Code am Eintrag: Er wird auf der
        // nächsten Seite gebraucht — also in die Zwischenablage.
        if (codeId == null && code.isNotEmpty()) codeKopieren(code)

        if (!gesetzt) return fehler("Der Eintrag hat nichts, was in diese Felder passt.")

        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, bau.build()))
        finish()
    }

    /**
     * Legt den Einmalcode in die Zwischenablage — als vertraulich markiert,
     * damit Android ihn nicht in der Vorschau zeigt — und räumt ihn nach
     * 30 Sekunden wieder weg, sofern dort noch unser Code liegt.
     */
    private fun codeKopieren(code: String) {
        val ablage = getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText("Einmalcode", code)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        ablage.setPrimaryClip(clip)
        Toast.makeText(applicationContext, "Einmalcode kopiert — 30 Sekunden gültig", Toast.LENGTH_LONG).show()

        Handler(Looper.getMainLooper()).postDelayed({
            val jetzt = ablage.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
            if (jetzt == code && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) ablage.clearPrimaryClip()
        }, 30_000)
    }

    /* ---------- Werkzeug ---------- */

    /** Die typsichere Fassung gibt es erst ab Android 13. */
    @Suppress("DEPRECATION")
    private fun feldId(name: String): AutofillId? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(name, AutofillId::class.java)
        } else {
            intent.getParcelableExtra(name)
        }

    private fun fehler(text: String) {
        Toast.makeText(applicationContext, text, Toast.LENGTH_LONG).show()
        abbrechen()
    }

    private fun abbrechen() {
        setResult(RESULT_CANCELED)
        finish()
    }
}
