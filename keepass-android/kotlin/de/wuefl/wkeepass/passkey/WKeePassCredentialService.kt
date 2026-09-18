package de.wuefl.wkeepass.passkey

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import de.wuefl.wkeepass.kern.Kern
import org.json.JSONObject

/**
 * WKeePass als Passkey-Anbieter für ganz Android (ab Android 14).
 *
 * Fragt eine App oder ein Browser nach einem Passkey, sammelt Android bei
 * allen eingetragenen Anbietern Vorschläge ein und zeigt sie gemeinsam an.
 * Dieser Dienst liefert unsere — aber noch **ohne** Signatur. Die entsteht
 * erst in der [PasskeyActivity], nachdem der Nutzer gewählt und sich
 * ausgewiesen hat.
 *
 * Die Passkeys selbst liegen in der kdbx-Datei, in denselben Feldern wie bei
 * KeePassXC (`passkey.rs`). Was hier angelegt wird, kennt der Desktop, und
 * umgekehrt.
 */
class WKeePassCredentialService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        try {
            callback.onResult(Vorschlaege.bauen(this, request))
        } catch (e: Throwable) {
            callback.onError(GetCredentialUnknownException(e.message))
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            // Passwörter über den Credential Manager bedienen wir nicht —
            // dafür ist Autofill da.
            callback.onResult(BeginCreateCredentialResponse.Builder().build())
            return
        }
        try {
            val status = Kern.frage { Kern.status() }.optString("status")
            val ziel = Intent(this, PasskeyActivity::class.java)
                .putExtra(PasskeyActivity.EXTRA_MODUS, PasskeyActivity.MODUS_ANLEGEN)
            val absicht = PendingIntent.getActivity(
                this, 1, ziel, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            val eintrag = CreateEntry.Builder("WKeePass", absicht)
                .setDescription(
                    if (status == "offen") "In der geöffneten Datenbank speichern"
                    else "WKeePass ist gesperrt — erst entsperren"
                )
                .build()
            callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(eintrag).build())
        } catch (e: Throwable) {
            callback.onError(CreateCredentialUnknownException(e.message))
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Wir merken uns keine Sitzung, also gibt es nichts zu vergessen.
        callback.onResult(null)
    }
}

/**
 * Die Vorschläge für eine Anmeldung — gebraucht vom Dienst und, nach dem
 * Entsperren, von der Activity.
 */
object Vorschlaege {

    fun bauen(context: Context, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
        val antwort = BeginGetCredentialResponse.Builder()
        val eintraege = mutableListOf<CredentialEntry>()

        val status = Kern.frage { Kern.status() }.optString("status")
        val optionen = request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()
        if (optionen.isEmpty()) return antwort.build()

        if (status != "offen") {
            // Gesperrt: eine Zeile „entsperren". Nach dem Entsperren liefert
            // die Activity die echten Vorschläge nach.
            val ziel = Intent(context, PasskeyActivity::class.java)
                .putExtra(PasskeyActivity.EXTRA_MODUS, PasskeyActivity.MODUS_ENTSPERREN)
            val absicht = PendingIntent.getActivity(
                context, 2, ziel, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            return antwort.addAuthenticationAction(AuthenticationAction("WKeePass entsperren", absicht)).build()
        }

        for (option in optionen) {
            val anfrage = JSONObject(option.requestJson)
            val rpId = anfrage.optString("rpId")
            if (rpId.isEmpty()) continue

            // Nennt die Gegenstelle erlaubte Kennungen, kommen nur die in Frage.
            val erlaubt = anfrage.optJSONArray("allowCredentials")?.let { liste ->
                (0 until liste.length()).map { liste.getJSONObject(it).optString("id") }.toSet()
            }.orEmpty()

            val passkeys = Kern.frage { Kern.passkeys(rpId) }.optJSONArray("passkeys") ?: continue
            for (i in 0 until passkeys.length()) {
                val pk = passkeys.getJSONObject(i)
                val id = pk.optString("credentialId")
                if (erlaubt.isNotEmpty() && id !in erlaubt) continue

                val ziel = Intent(context, PasskeyActivity::class.java)
                    .putExtra(PasskeyActivity.EXTRA_MODUS, PasskeyActivity.MODUS_ANMELDEN)
                    .putExtra(PasskeyActivity.EXTRA_CREDENTIAL_ID, id)
                val absicht = PendingIntent.getActivity(
                    context, id.hashCode(), ziel,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
                val name = pk.optString("userName").ifEmpty { rpId }
                eintraege += PublicKeyCredentialEntry.Builder(context, name, absicht, option)
                    .setDisplayName("WKeePass")
                    .build()
            }
        }
        return antwort.setCredentialEntries(eintraege).build()
    }
}
