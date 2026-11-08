package de.wuefl.wkeepass.autofill

import android.app.assist.AssistStructure
import android.view.View
import android.view.autofill.AutofillId

/**
 * Sucht im View-Baum einer Autofill-Anfrage die Anmeldefelder.
 *
 * Android liefert die ganze Ansicht als Baum; bei einer Web-Seite in einer
 * App sind das schnell hunderte Knoten. Benutzername und Passwort werden in
 * dieser Reihenfolge erkannt:
 *
 *   1. `autofillHints`: Die App benennt das Feld ausdrücklich; dann gilt
 *      nur dieser Hinweis.
 *   2. Der Eingabetyp: `TYPE_TEXT_VARIATION_PASSWORD` kennzeichnet
 *      Passwortfelder eindeutig.
 *   3. Bezeichner wie `login` oder `benutzer` (Heuristik, letzte Stufe).
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
         * Ohne Passwortfeld wird nichts angeboten. Ein Formular nur mit
         * Benutzernamen ist meist der erste Schritt einer zweistufigen
         * Anmeldung.
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
     * Läuft den Baum in Anzeigereihenfolge ab. Bereits Gefundenes wird nicht
     * überschrieben; bei mehreren Passwortfeldern gilt das erste.
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
        // Wurzelknoten des Dokuments; sie ist genauer als der Paketname.
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
            // Hinweise für Einmalcodes (`smsOTPCode`, `2faAppOTPCode`, …) gibt
            // es nur in androidx; Seiten melden `one-time-code` über das
            // autocomplete-Attribut.
            if (hinweis.contains("otp", ignoreCase = true) || hinweis == "one-time-code") return Art.CODE
            when (hinweis) {
                View.AUTOFILL_HINT_PASSWORD -> return Art.PASSWORT
                View.AUTOFILL_HINT_USERNAME,
                View.AUTOFILL_HINT_EMAIL_ADDRESS -> return Art.BENUTZER
            }
        }

        // Nur Textfelder kommen in Frage, keine Knöpfe oder Beschriftungen.
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
