package de.wuefl.wkeepass.kern

import android.content.Context
import android.content.Intent
import android.widget.Toast
import org.json.JSONObject

/**
 * Die Tür zum Rust-Kern für alles, was **ohne** Webview läuft: Autofill und
 * Passkeys.
 *
 * Gegenstück: `src-tauri/src/android_services.rs`. Jede Funktion gibt JSON
 * zurück; ein Fehler steht unter `fehler`, ein Zustand wie „Datenbank zu"
 * unter `status`. Ausnahmen gibt es über diese Grenze nicht.
 *
 * ## Warum die Bibliothek hier geladen wird
 *
 * Android kann unseren Dienst starten, ohne dass die App je lief. Dann ist
 * die Rust-Bibliothek noch nicht im Prozess, und der erste Aufruf endete
 * mit `UnsatisfiedLinkError`. Laden ist harmlos, wenn sie schon da ist.
 * Der Kern antwortet dann mit `status: "aus"` — die Datenbank ist ja zu —,
 * und wir holen die App nach vorn.
 */
object Kern {

    private val geladen: Boolean = try {
        System.loadLibrary("wkeepass_lib")
        true
    } catch (e: Throwable) {
        false
    }

    @JvmStatic external fun status(): String
    @JvmStatic external fun treffer(paket: String, web: String): String
    @JvmStatic external fun zugang(id: String, paket: String, merken: Boolean): String
    @JvmStatic external fun speichern(paket: String, web: String, benutzer: String, passwort: String): String
    @JvmStatic external fun passkeys(rpId: String): String
    @JvmStatic external fun passkeyAnlegen(anfrage: String, herkunft: String, clientHash: String): String
    @JvmStatic external fun passkeyAnmelden(anfrage: String, credentialId: String, herkunft: String, clientHash: String): String

    /** Ruft den Kern und liest die Antwort — auch dann, wenn er fehlt. */
    fun frage(aufruf: () -> String): JSONObject {
        if (!geladen) return JSONObject().put("status", "aus")
        return try {
            JSONObject(aufruf())
        } catch (e: Throwable) {
            JSONObject().put("fehler", e.message ?: e.toString())
        }
    }

    /** Ist die Datenbank zu (oder die App gar nicht gestartet)? */
    fun gesperrt(antwort: JSONObject): Boolean =
        antwort.optString("status") in setOf("zu", "aus")

    /**
     * Holt die App nach vorn, damit der Nutzer entsperrt. Danach tippt er
     * das Feld erneut an — dann ist die Datenbank offen.
     */
    fun appOeffnen(context: Context) {
        val start = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        start.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(start)
        Toast.makeText(
            context,
            "WKeePass entsperren, dann erneut antippen.",
            Toast.LENGTH_LONG,
        ).show()
    }
}
