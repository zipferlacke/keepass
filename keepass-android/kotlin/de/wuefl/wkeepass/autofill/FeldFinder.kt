package de.wuefl.wkeepass.autofill

import android.app.assist.AssistStructure
import android.view.View
import android.view.autofill.AutofillId

/**
 * Sucht in dem Baum, den Android mitschickt, die Anmeldefelder.
 *
 * Android liefert keine Liste von Feldern, sondern die ganze Ansicht als
 * Baum — bei einer Web-Seite in einer App sind das schnell hunderte Knoten.
 * Darin ist zu finden, wo Benutzername und Passwort hingehören.
 *
 * Es gibt drei Wege dorthin, und sie sind unterschiedlich verlässlich:
 *
 *   1. `autofillHints` — die App sagt es ausdrücklich. Wenn vorhanden, gilt
 *      das und sonst nichts.
 *   2. Der Eingabetyp. `TYPE_TEXT_VARIATION_PASSWORD` ist eindeutig, denn
 *      davon hängt ab, ob Zeichen als Punkte erscheinen.
 *   3. Raten anhand von Bezeichnern wie `login` oder `benutzer`. Das ist der
 *      letzte Weg, und er liegt bewusst hinten.
 */
object FeldFinder {

    /** Was gefunden wurde. Beide Felder können fehlen. */
    data class Felder(
        val benutzer: AutofillId? = null,
        val passwort: AutofillId? = null,
        /** Die Webadresse, falls die App eine mitgeschickt hat. */
        val webAdresse: String? = null,
        /** Was in den Feldern steht — nur beim Speichern gefragt. */
        val benutzerWert: String? = null,
        val passwortWert: String? = null,
        /** Feld für den Einmalcode (TOTP) — meist auf einer eigenen Seite. */
        val code: AutofillId? = null,
    ) {
        /**
         * Ohne Passwortfeld ist nichts zu holen.
         *
         * Ein Formular mit nur einem Benutzernamen ist meist die erste
         * Hälfte einer zweistufigen Anmeldung. Dort etwas anzubieten, ohne
         * zu wissen, ob überhaupt ein Passwort folgt, führt zu Vorschlägen
         * an Stellen, wo sie stören.
         */
        val brauchbar: Boolean get() = passwort != null || code != null

        /** Alle Felder, die ein Vorschlag bedienen kann. */
        val ids: List<AutofillId> get() = listOfNotNull(benutzer, passwort, code)
    }

    /** Bezeichner, die auf ein Benutzernamensfeld hindeuten. */
    private val BENUTZER_WORTE = listOf(
        "username", "user_name", "userid", "user_id", "login", "email",
        "e-mail", "benutzer", "anmeldung", "kennung"
    )

    fun suche(struktur: AssistStructure): Felder {
        var gefunden = Felder()

        for (i in 0 until struktur.windowNodeCount) {
            gefunden = durchlaufe(struktur.getWindowNodeAt(i).rootViewNode, gefunden)
        }
        return gefunden
    }

    /**
     * Läuft den Baum ab.
     *
     * Bereits Gefundenes wird **nicht** überschrieben. Der erste Treffer
     * gewinnt, und der Baum kommt in Anzeigereihenfolge — bei zwei
     * Passwortfeldern (Anmeldung oben, Registrierung darunter) ist das
     * obere gemeint.
     */
    private fun durchlaufe(knoten: AssistStructure.ViewNode, bisher: Felder): Felder {
        var stand = bisher

        val id = knoten.autofillId
        if (id != null) {
            when (deute(knoten)) {
                Art.BENUTZER -> if (stand.benutzer == null) {
                    stand = stand.copy(benutzer = id, benutzerWert = wert(knoten))
                }
                Art.PASSWORT -> if (stand.passwort == null) {
                    stand = stand.copy(passwort = id, passwortWert = wert(knoten))
                }
                Art.CODE -> if (stand.code == null) stand = stand.copy(code = id)
                Art.UNBEKANNT -> {}
            }
        }

        // Browser und Apps mit eingebetteten Seiten hängen die Adresse an den
        // Wurzelknoten des Dokuments. Sie ist die genauere Kennung als der
        // Paketname — damit greift dieselbe Suche wie auf dem Desktop.
        knoten.webDomain?.takeIf { it.isNotBlank() }?.let {
            if (stand.webAdresse == null) stand = stand.copy(webAdresse = it)
        }

        for (i in 0 until knoten.childCount) {
            stand = durchlaufe(knoten.getChildAt(i), stand)
        }
        return stand
    }

    private fun wert(knoten: AssistStructure.ViewNode): String? =
        knoten.autofillValue?.takeIf { it.isText }?.textValue?.toString()?.takeIf { it.isNotEmpty() }

    private enum class Art { BENUTZER, PASSWORT, CODE, UNBEKANNT }

    /** Bezeichner, die auf ein Feld für den Einmalcode hindeuten. */
    private val CODE_WORTE = listOf(
        "one-time-code", "onetimecode", "one_time", "otp", "totp", "2fa", "mfa", "tfa",
        "einmal", "authenticator", "verification_code", "verificationcode", "auth_code", "authcode"
    )

    private fun deute(knoten: AssistStructure.ViewNode): Art {
        // 1. Die App sagt es selbst.
        knoten.autofillHints?.forEach { hinweis ->
            // Die Hinweise für Einmalcodes haben in `View` keine Konstante,
            // nur in androidx: `smsOTPCode`, `2faAppOTPCode`, … — und Seiten
            // melden `one-time-code` über ihr autocomplete-Attribut.
            if (hinweis.contains("otp", ignoreCase = true) || hinweis == "one-time-code") return Art.CODE
            when (hinweis) {
                View.AUTOFILL_HINT_PASSWORD -> return Art.PASSWORT
                View.AUTOFILL_HINT_USERNAME,
                View.AUTOFILL_HINT_EMAIL_ADDRESS -> return Art.BENUTZER
            }
        }

        // Nur Textfelder kommen überhaupt in Frage. Ohne diese Schranke
        // landen Knöpfe und Beschriftungen in der Auswahl.
        if (knoten.autofillType != View.AUTOFILL_TYPE_TEXT) return Art.UNBEKANNT

        // 2. Der Eingabetyp. Punkte statt Zeichen heißt Passwort.
        val typ = knoten.inputType
        val klasse = typ and android.text.InputType.TYPE_MASK_CLASS
        val variante = typ and android.text.InputType.TYPE_MASK_VARIATION

        val istPasswort = when (klasse) {
            android.text.InputType.TYPE_CLASS_TEXT -> variante in setOf(
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD,
                android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
                android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
            )
            android.text.InputType.TYPE_CLASS_NUMBER ->
                variante == android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            else -> false
        }
        if (istPasswort) return Art.PASSWORT

        // 3. Raten. Alles, woran die App sich erkennen lässt, in einen Topf —
        // bei Webseiten auch die HTML-Attribute (name, id, autocomplete).
        val html = knoten.htmlInfo?.attributes.orEmpty()
            .filter { it.first in setOf("name", "id", "autocomplete", "placeholder", "aria-label") }
            .map { it.second }
        val worte = (listOfNotNull(
            knoten.idEntry,
            knoten.hint,
            knoten.contentDescription?.toString()
        ) + html).joinToString(" ").lowercase()

        if (CODE_WORTE.any { worte.contains(it) }) return Art.CODE
        if (BENUTZER_WORTE.any { worte.contains(it) }) return Art.BENUTZER

        return Art.UNBEKANNT
    }
}
