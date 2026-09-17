package de.wuefl.wkeepass.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews

/**
 * Unsere Seite des Autofill-Anschlusses von Android.
 *
 * Das System erzeugt diese Klasse selbst und ruft sie an, während der Nutzer
 * in einer **fremden** App vor einem Anmeldefeld steht. Unsere Anwendung
 * läuft dabei nicht — kein Fenster, kein Webview, oft nicht einmal ein
 * Prozess.
 *
 * ## Warum hier kein Passwort steht
 *
 * Naheliegend wäre, gleich die passenden Zugangsdaten in die Antwort zu
 * legen. Das wäre falsch, und zwar aus zwei Gründen.
 *
 * Erstens ist die Datenbank verschlüsselt. Wer sie öffnen will, braucht das
 * Master-Passwort, und danach wird hier niemand gefragt.
 *
 * Zweitens — und das wiegt schwerer — sieht die anfragende App die Antwort.
 * Ein `Dataset` mit Klartextwerten geht durch ihre Hände, bevor der Nutzer
 * überhaupt etwas ausgewählt hat. Eine App, die ein Anmeldefeld nachbaut,
 * bekäme so jedes passende Passwort geschenkt.
 *
 * Deshalb der eingeführte Weg: Das `Dataset` trägt nur eine Beschriftung und
 * eine **Authentifizierung**. Tippt der Nutzer darauf, startet Android
 * unsere `AusfuellActivity`. Dort — in unserem Prozess, hinter unserer
 * Legitimation — entsteht das Dataset mit den echten Werten, und nur das
 * ausgewählte.
 *
 * ## Stand
 *
 * Gerüst. Was fehlt, steht als `TODO` an Ort und Stelle, und im README
 * stehen die beiden großen Lücken: der Zugriff auf die Datei über
 * `content://` und der Android Keystore anstelle des Secret Service.
 */
class WKeePassAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        // Der letzte Zustand ist der aktuelle. Frühere Einträge in der Liste
        // stammen aus vorherigen Runden derselben Ansicht.
        val struktur = request.fillContexts.lastOrNull()?.structure
        if (struktur == null) {
            callback.onSuccess(null)
            return
        }

        val felder = FeldFinder.suche(struktur)

        // `null` heißt „für dieses Formular haben wir nichts". Das ist kein
        // Fehler und muss auch keiner sein — Android fragt bei jedem
        // Textfeld nach, auch bei Suchschlitzen und Notizen.
        if (!felder.brauchbar) {
            callback.onSuccess(null)
            return
        }

        val kennung = struktur.activityComponent?.packageName ?: packageName

        // TODO: Statt einer festen Zeile die Zahl der Treffer anzeigen.
        //       Dafür muss der Kern ohne Master-Passwort auskunftsfähig sein
        //       — also entweder ein offener Tresor im Speicher oder ein
        //       Verzeichnis, das nur Titel und Zuordnung kennt. Solange das
        //       nicht steht, ist eine unbestimmte Zeile ehrlicher als eine
        //       Zahl, die nicht stimmt.
        val zeile = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "WKeePass öffnen")
        }

        val weiter = Intent(this, AusfuellActivity::class.java).apply {
            putExtra(EXTRA_PAKET, kennung)
            putExtra(EXTRA_WEB, felder.webAdresse)
            putExtra(EXTRA_BENUTZER_ID, felder.benutzer)
            putExtra(EXTRA_PASSWORT_ID, felder.passwort)
        }

        val absicht = PendingIntent.getActivity(
            this,
            0,
            weiter,
            // MUTABLE, weil Android das Ergebnis in denselben Intent legt.
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )

        val antwort = FillResponse.Builder()
            .setAuthentication(
                listOfNotNull(felder.benutzer, felder.passwort).toTypedArray(),
                absicht.intentSender,
                zeile
            )
            .build()

        callback.onSuccess(antwort)
    }

    /**
     * Nach dem Absenden eines Formulars: Android bietet an, das Eingetippte
     * zu übernehmen.
     *
     * TODO: An `vault_save_entry` weiterreichen — mit Rückfrage. Ungefragt
     *       Einträge anzulegen füllt die Datenbank mit Halbfertigem.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onFailure("Speichern ist noch nicht eingebaut.")
    }

    companion object {
        const val EXTRA_PAKET = "de.wuefl.wkeepass.PAKET"
        const val EXTRA_WEB = "de.wuefl.wkeepass.WEB"
        const val EXTRA_BENUTZER_ID = "de.wuefl.wkeepass.BENUTZER_ID"
        const val EXTRA_PASSWORT_ID = "de.wuefl.wkeepass.PASSWORT_ID"

        /**
         * Damit `SaveInfo` beim Einbauen von `onSaveRequest` nicht neu
         * nachgeschlagen werden muss: Es gehört an die `FillResponse` und
         * nennt die Felder, deren Änderung das Angebot auslöst.
         */
        const val SPEICHERN_ART = SaveInfo.SAVE_DATA_TYPE_USERNAME or
            SaveInfo.SAVE_DATA_TYPE_PASSWORD
    }
}
