package de.wuefl.wkeepass.passkey

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.widget.Toast
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import de.wuefl.wkeepass.kern.Kern
import de.wuefl.wkeepass.sicherheit.Bestaetigung
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Hier entsteht die Signatur — nach Auswahl und Ausweis.
 *
 * Drei Aufgaben, je nachdem, welche Zeile der Nutzer angetippt hat:
 *
 * ```text
 * anmelden     Passkey gewählt → Ausweis → signieren → zurück an Android
 * anlegen      „In WKeePass speichern" → Ausweis → Schlüssel erzeugen
 * entsperren   Datenbank war zu → App nach vorn, oder, wenn sie inzwischen
 *              offen ist, die echten Vorschläge nachliefern
 * ```
 *
 * ## Woher die Herkunft kommt
 *
 * WebAuthn bindet jede Signatur an die Herkunft der Anfrage. Bei Apps ist
 * das `android:apk-key-hash:<SHA-256 des Signaturzertifikats>` — die
 * Gegenstelle prüft ihn gegen ihre Digital Asset Links. Browser dagegen
 * bauen das clientDataJSON selbst und schicken nur dessen Hash. Den nehmen
 * wir **nur** von Aufrufern, deren Herkunft Android selbst bestätigt hat —
 * sonst könnte jede App einen Hash für `https://bank.de` vorlegen und sich
 * eine gültige Anmeldung erschleichen.
 */
class PasskeyActivity : Activity() {

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        when (intent.getStringExtra(EXTRA_MODUS)) {
            MODUS_ANMELDEN -> anmelden()
            MODUS_ANLEGEN -> anlegen()
            MODUS_ENTSPERREN -> entsperren()
            else -> fertig(RESULT_CANCELED)
        }
    }

    private fun anmelden() {
        val anfrage = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = anfrage?.credentialOptions?.filterIsInstance<GetPublicKeyCredentialOption>()?.firstOrNull()
        if (anfrage == null || option == null) return abbruchGet("Keine Passkey-Anfrage erhalten.")

        val (herkunft, hash) = herkunft(anfrage.callingAppInfo, option.clientDataHash)
            ?: return abbruchGet("Der Aufrufer ist nicht vertrauenswürdig.")

        val rp = JSONObject(option.requestJson).optString("rpId")
        Bestaetigung.fragen(this, "Anmelden bei $rp") { ok ->
            if (!ok) return@fragen abbruchGet(null)

            val id = intent.getStringExtra(EXTRA_CREDENTIAL_ID) ?: ""
            val antwort = Kern.frage { Kern.passkeyAnmelden(option.requestJson, id, herkunft, hash) }
            if (Kern.gesperrt(antwort)) {
                Kern.appOeffnen(this)
                return@fragen abbruchGet(null)
            }
            if (antwort.has("fehler")) return@fragen abbruchGet(antwort.optString("fehler"))

            val ergebnis = Intent()
            PendingIntentHandler.setGetCredentialResponse(
                ergebnis, GetCredentialResponse(PublicKeyCredential(antwort.toString()))
            )
            setResult(RESULT_OK, ergebnis)
            finish()
        }
    }

    private fun anlegen() {
        val anfrage = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val aufruf = anfrage?.callingRequest as? CreatePublicKeyCredentialRequest
        if (anfrage == null || aufruf == null) return abbruchCreate("Keine Passkey-Anfrage erhalten.")

        if (Kern.gesperrt(Kern.frage { Kern.status() })) {
            Kern.appOeffnen(this)
            return abbruchCreate(null)
        }

        val (herkunft, hash) = herkunft(anfrage.callingAppInfo, aufruf.clientDataHash)
            ?: return abbruchCreate("Der Aufrufer ist nicht vertrauenswürdig.")

        val rp = JSONObject(aufruf.requestJson).optJSONObject("rp")?.optString("id") ?: ""
        Bestaetigung.fragen(this, "Passkey für $rp anlegen") { ok ->
            if (!ok) return@fragen abbruchCreate(null)

            val antwort = Kern.frage { Kern.passkeyAnlegen(aufruf.requestJson, herkunft, hash) }
            if (Kern.gesperrt(antwort)) {
                Kern.appOeffnen(this)
                return@fragen abbruchCreate(null)
            }
            if (antwort.has("fehler")) return@fragen abbruchCreate(antwort.optString("fehler"))

            val ergebnis = Intent()
            PendingIntentHandler.setCreateCredentialResponse(
                ergebnis, CreatePublicKeyCredentialResponse(antwort.toString())
            )
            setResult(RESULT_OK, ergebnis)
            finish()
        }
    }

    /**
     * Die Zeile „WKeePass entsperren" wurde angetippt. Ist die Datenbank
     * inzwischen offen, liefern wir die Vorschläge nach; sonst App nach vorn.
     */
    private fun entsperren() {
        val anfrage = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
        if (anfrage == null || Kern.gesperrt(Kern.frage { Kern.status() })) {
            Kern.appOeffnen(this)
            return fertig(RESULT_CANCELED)
        }
        val ergebnis = Intent()
        PendingIntentHandler.setBeginGetCredentialResponse(ergebnis, Vorschlaege.bauen(this, anfrage))
        setResult(RESULT_OK, ergebnis)
        finish()
    }

    /**
     * Herkunft und clientDataHash für den Kern — oder `null`, wenn der
     * Aufrufer einen Hash vorlegt, ohne dass Android seine Herkunft kennt.
     */
    private fun herkunft(app: CallingAppInfo, clientHash: ByteArray?): Pair<String, String>? {
        if (clientHash != null) {
            if (!app.isOriginPopulated()) return null
            return "" to Base64.encodeToString(clientHash, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        }
        val zertifikat = app.signingInfo.apkContentsSigners.firstOrNull()?.toByteArray() ?: return null
        val hash = MessageDigest.getInstance("SHA-256").digest(zertifikat)
        val text = Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        return "android:apk-key-hash:$text" to ""
    }

    private fun abbruchGet(grund: String?) {
        val ergebnis = Intent()
        PendingIntentHandler.setGetCredentialException(
            ergebnis,
            if (grund == null) GetCredentialCancellationException() else GetCredentialUnknownException(grund),
        )
        grund?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
        setResult(RESULT_OK, ergebnis)
        finish()
    }

    private fun abbruchCreate(grund: String?) {
        val ergebnis = Intent()
        PendingIntentHandler.setCreateCredentialException(
            ergebnis,
            if (grund == null) CreateCredentialCancellationException() else CreateCredentialUnknownException(grund),
        )
        grund?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
        setResult(RESULT_OK, ergebnis)
        finish()
    }

    private fun fertig(code: Int) {
        setResult(code)
        finish()
    }

    companion object {
        const val EXTRA_MODUS = "de.wuefl.wkeepass.passkey.MODUS"
        const val EXTRA_CREDENTIAL_ID = "de.wuefl.wkeepass.passkey.CREDENTIAL_ID"
        const val MODUS_ANMELDEN = "anmelden"
        const val MODUS_ANLEGEN = "anlegen"
        const val MODUS_ENTSPERREN = "entsperren"
    }
}
