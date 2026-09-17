package de.wuefl.wkeepass.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager

/**
 * Hier entsteht das, was tatsächlich in die fremde App geht.
 *
 * Der Dienst hat vorher nur eine Zeile mit einer Authentifizierung
 * geliefert; die anfragende App hat kein Passwort gesehen. Tippt der Nutzer
 * darauf, startet Android **diese** Activity — in unserem Prozess, unter
 * unserer Kontrolle.
 *
 * Was hier passiert, ist dasselbe wie im kleinen Fenster auf dem Desktop:
 * entsperren, wenn nötig; auswählen, wenn mehrere passen; legitimieren, wenn
 * es die Einstellung verlangt.
 *
 * ## Wie das Ergebnis zurückkommt
 *
 * Nicht als Rückgabewert, sondern als `Dataset` unter
 * `AutofillManager.EXTRA_AUTHENTICATION_RESULT` im Ergebnis-Intent. Android
 * setzt es dann in die Felder ein, deren `AutofillId` der Dienst
 * mitgeschickt hat.
 *
 * `RESULT_CANCELED` heißt: nichts einsetzen. Das ist auch die richtige
 * Antwort, wenn der Nutzer abbricht oder die Legitimation scheitert — ein
 * Fehler wäre es nicht.
 *
 * ## Stand
 *
 * Gerüst. Der Ablauf steht, der Inhalt fehlt: Ohne Zugriff auf die
 * kdbx-Datei über `content://` gibt es nichts auszuwählen. Siehe README.
 */
class AusfuellActivity : Activity() {

    private var benutzerId: AutofillId? = null
    private var passwortId: AutofillId? = null

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)

        val paket = intent.getStringExtra(WKeePassAutofillService.EXTRA_PAKET)
        val web = intent.getStringExtra(WKeePassAutofillService.EXTRA_WEB)

        benutzerId = intent.getParcelableExtra(
            WKeePassAutofillService.EXTRA_BENUTZER_ID, AutofillId::class.java
        )
        passwortId = intent.getParcelableExtra(
            WKeePassAutofillService.EXTRA_PASSWORT_ID, AutofillId::class.java
        )

        // TODO: Der eigentliche Ablauf.
        //
        //   1. Datenbank offen? Sonst entsperren — PIN, Master-Passwort oder
        //      BiometricPrompt. Dieselben Wege wie im kleinen Fenster.
        //   2. Passende Einträge suchen. Die Webadresse ist die genauere
        //      Kennung; ohne sie bleibt `androidapp://<paket>`, und der
        //      Paketname allein ist ein Hinweis, keine Kennung — siehe die
        //      Anmerkung zu Digital Asset Links im README.
        //   3. Bei mehreren auswählen lassen, bei genau einem direkt weiter.
        //   4. `fertig(...)` mit den Klartextwerten.
        //
        // Bis dahin: nichts einsetzen. Das ist die sichere Antwort.
        abbrechen()
    }

    /** Übergibt die Werte an Android und schließt. */
    @Suppress("unused")
    private fun fertig(benutzer: String?, passwort: String?) {
        val bau = android.service.autofill.Dataset.Builder()

        // Die Werte gehen an genau die Felder, die der Dienst benannt hat.
        // Ein Feld, das nicht gefunden wurde, bleibt leer — dann tippt der
        // Nutzer den Benutzernamen eben selbst.
        benutzerId?.let { id ->
            benutzer?.let { bau.setValue(id, android.view.autofill.AutofillValue.forText(it)) }
        }
        passwortId?.let { id ->
            passwort?.let { bau.setValue(id, android.view.autofill.AutofillValue.forText(it)) }
        }

        setResult(
            RESULT_OK,
            Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, bau.build())
        )
        finish()
    }

    private fun abbrechen() {
        setResult(RESULT_CANCELED)
        finish()
    }
}
