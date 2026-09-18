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
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import de.wuefl.wkeepass.R
import de.wuefl.wkeepass.kern.Kern

/**
 * Unsere Seite des Autofill-Anschlusses von Android.
 *
 * Das System erzeugt diese Klasse selbst und ruft sie an, während der Nutzer
 * in einer **fremden** App vor einem Anmeldefeld steht.
 *
 * ## Warum hier kein Passwort steht
 *
 * Die anfragende App sieht die Antwort. Ein `Dataset` mit Klartextwerten
 * ginge durch ihre Hände, bevor der Nutzer überhaupt etwas ausgewählt hat —
 * eine App, die ein Anmeldefeld nachbaut, bekäme so jedes passende Passwort
 * geschenkt.
 *
 * Deshalb der eingeführte Weg: Die Antwort trägt nur eine Zeile und eine
 * **Authentifizierung**. Tippt der Nutzer darauf, startet Android unsere
 * [AusfuellActivity]. Dort, in unserem Prozess, entsteht das Dataset mit
 * den echten Werten — und nur mit denen des gewählten Eintrags.
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

        // `null` heißt „für dieses Formular haben wir nichts". Android fragt
        // bei jedem Textfeld nach, auch bei Suchschlitzen und Notizen.
        if (!felder.brauchbar) {
            callback.onSuccess(null)
            return
        }

        val paket = struktur.activityComponent?.packageName ?: ""

        // Uns selbst nicht ausfüllen — das Master-Passwort-Feld der App
        // bekäme sonst einen Vorschlag aus der Datenbank, die es öffnen soll.
        if (paket == packageName) {
            callback.onSuccess(null)
            return
        }

        val web = felder.webAdresse ?: ""
        val ids = felder.ids.toTypedArray()
        val antwort = FillResponse.Builder()

        val stand = Kern.frage { Kern.treffer(paket, web) }
        if (Kern.gesperrt(stand) || stand.has("fehler")) {
            // Gesperrt: eine Zeile, die zum Entsperren führt. Konten zeigen
            // ginge nicht — ohne offene Datenbank kennen wir keine.
            antwort.addDataset(vorschlag(ids, zeile("WKeePass entsperren", "Danach erneut antippen"), absicht(felder, paket, null)))
        } else {
            val liste = stand.optJSONArray("eintraege")
            val passend = (0 until (liste?.length() ?: 0))
                .map { liste!!.getJSONObject(it) }
                .filter { it.optBoolean("passend") }
                // Nur ein Code-Feld? Dann zählen nur Einträge mit TOTP.
                .filter { felder.passwort != null || it.optBoolean("totp") }
                .take(MAX_VORSCHLAEGE)

            // Je passendem Konto eine Zeile mit seinem Namen — die Werte
            // entstehen trotzdem erst nach dem Antippen, in der Activity.
            for (eintrag in passend) {
                val benutzer = eintrag.optString("benutzer")
                val titel = eintrag.optString("titel")
                val oben = when {
                    felder.passwort == null -> "Einmalcode · $titel"
                    benutzer.isNotEmpty() -> benutzer
                    else -> titel
                }
                val unten = if (felder.passwort == null || benutzer.isEmpty()) "WKeePass" else "$titel · WKeePass"
                antwort.addDataset(vorschlag(ids, zeile(oben, unten), absicht(felder, paket, eintrag.optString("id"))))
            }

            // Immer dabei: an jedes andere Konto herankommen.
            antwort.addDataset(
                vorschlag(ids, zeile(if (passend.isEmpty()) "Zugang wählen …" else "Anderen Eintrag wählen …", "WKeePass"), absicht(felder, paket, null))
            )
        }

        // Nach dem Absenden bietet Android an, das Eingetippte zu übernehmen
        // — dann landet es in `onSaveRequest`. Nur mit Passwortfeld.
        val speicherbar = listOfNotNull(felder.benutzer, felder.passwort).toTypedArray()
        if (felder.passwort != null) {
            antwort.setSaveInfo(SaveInfo.Builder(SPEICHERN_ART, speicherbar).build())
        }

        callback.onSuccess(antwort.build())
    }

    /**
     * Nach dem Absenden eines Formulars hat der Nutzer „Speichern"
     * angetippt: neuer Eintrag in der offenen Datenbank.
     *
     * Android fragt vorher selbst nach — ungefragt landet hier nichts.
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val struktur = request.fillContexts.lastOrNull()?.structure
        if (struktur == null) {
            callback.onFailure("Kein Formular erkannt.")
            return
        }
        val felder = FeldFinder.suche(struktur)
        val passwort = felder.passwortWert
        if (passwort.isNullOrEmpty()) {
            callback.onFailure("Kein Passwort im Formular.")
            return
        }

        val paket = struktur.activityComponent?.packageName ?: ""
        val antwort = Kern.frage {
            Kern.speichern(paket, felder.webAdresse ?: "", felder.benutzerWert ?: "", passwort)
        }

        when {
            antwort.optBoolean("ok") -> callback.onSuccess()
            // Gesperrt: Der Kern hat es sich gemerkt und trägt es nach dem
            // Entsperren ein.
            antwort.optString("status") == "vorgemerkt" -> {
                android.widget.Toast.makeText(
                    this, "Gemerkt — wird beim nächsten Entsperren von WKeePass gespeichert.",
                    android.widget.Toast.LENGTH_LONG,
                ).show()
                callback.onSuccess()
            }
            Kern.gesperrt(antwort) -> callback.onFailure("WKeePass läuft nicht — nichts gespeichert.")
            else -> callback.onFailure(antwort.optString("fehler", "Nicht gespeichert."))
        }
    }

    /** Eine Vorschlagszeile im Stil der App: Symbol, oben fett, unten leise. */
    private fun zeile(oben: String, unten: String) =
        RemoteViews(packageName, R.layout.wkeepass_vorschlag).apply {
            setTextViewText(R.id.wkeepass_oben, oben)
            setTextViewText(R.id.wkeepass_unten, unten)
        }

    /**
     * Ein Vorschlag ohne Werte, aber mit Authentifizierung: Android startet
     * beim Antippen die Activity und setzt ein, was sie zurückgibt.
     */
    @Suppress("DEPRECATION")
    private fun vorschlag(ids: Array<AutofillId>, anzeige: RemoteViews, absicht: PendingIntent) =
        Dataset.Builder(anzeige).apply {
            ids.forEach { setValue(it, null) }
            setAuthentication(absicht.intentSender)
        }.build()

    private fun absicht(felder: FeldFinder.Felder, paket: String, eintrag: String?): PendingIntent {
        val weiter = Intent(this, AusfuellActivity::class.java).apply {
            putExtra(EXTRA_PAKET, paket)
            putExtra(EXTRA_WEB, felder.webAdresse)
            putExtra(EXTRA_BENUTZER_ID, felder.benutzer)
            putExtra(EXTRA_PASSWORT_ID, felder.passwort)
            putExtra(EXTRA_CODE_ID, felder.code)
            putExtra(EXTRA_EINTRAG, eintrag)
        }
        return PendingIntent.getActivity(
            this,
            // Je Vorschlag eine eigene Nummer — sonst überschreibt der
            // nächste die Extras des vorherigen.
            (paket + felder.webAdresse + felder.ids.joinToString() + eintrag).hashCode(),
            weiter,
            // MUTABLE, weil Android das Ergebnis in denselben Intent legt.
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
    }

    companion object {
        /** Mehr Zeilen verdecken die Seite, statt zu helfen. */
        private const val MAX_VORSCHLAEGE = 4

        const val EXTRA_CODE_ID = "de.wuefl.wkeepass.CODE_ID"
        const val EXTRA_EINTRAG = "de.wuefl.wkeepass.EINTRAG"
        const val EXTRA_PAKET = "de.wuefl.wkeepass.PAKET"
        const val EXTRA_WEB = "de.wuefl.wkeepass.WEB"
        const val EXTRA_BENUTZER_ID = "de.wuefl.wkeepass.BENUTZER_ID"
        const val EXTRA_PASSWORT_ID = "de.wuefl.wkeepass.PASSWORT_ID"

        const val SPEICHERN_ART = SaveInfo.SAVE_DATA_TYPE_USERNAME or
            SaveInfo.SAVE_DATA_TYPE_PASSWORD
    }
}
