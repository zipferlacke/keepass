package de.wuefl.wkeepass.kern

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import de.wuefl.wkeepass.R
import org.json.JSONObject

/**
 * Zugang zum Rust-Kern für alles, was ohne Webview läuft: Autofill und
 * Passkeys.
 *
 * Gegenstück: `src-tauri/src/android_services.rs`. Jede Funktion gibt JSON
 * zurück; ein Fehler steht unter `fehler`, ein Zustand wie „Datenbank zu"
 * unter `status`. Ausnahmen gibt es über diese Grenze nicht.
 *
 * ## Laden der Bibliothek
 *
 * Android kann den Dienst starten, ohne dass die App lief; dann ist die
 * Rust-Bibliothek noch nicht im Prozess (`UnsatisfiedLinkError`). Deshalb
 * wird sie hier geladen. Der Kern antwortet dann mit `status: "aus"`, und
 * [de.wuefl.wkeepass.system.Kaltstart] startet die App kurz.
 */
object Kern {

    private val geladen: Boolean = try {
        System.loadLibrary("wkeepass_lib")
        true
    } catch (e: Throwable) {
        false
    }

    @JvmStatic external fun status(): String
    @JvmStatic external fun aktivitaet(activity: Activity?)
    @JvmStatic external fun wege(): String
    @JvmStatic external fun entsperren(methode: String, geheimnis: String): String
    @JvmStatic external fun pruefen(methode: String, geheimnis: String): String
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

    /**
     * Fragt den Kern auf einem Arbeitsfaden und liefert die Antwort auf dem
     * Hauptfaden zurück.
     *
     * Der Kern kann warten müssen (Argon2 beim Speichern); auf dem Hauptfaden
     * stünde währenddessen die Anzeige. Deshalb nicht von dort aufrufen.
     */
    fun imHintergrund(aufruf: () -> String, dann: (JSONObject) -> Unit) {
        val haupt = Handler(Looper.getMainLooper())
        Thread {
            val antwort = frage(aufruf)
            haupt.post { dann(antwort) }
        }.start()
    }

    /**
     * Meldet die sichtbare Activity an, beim Verlassen mit `null` wieder ab.
     *
     * Systemdialoge (Fingerabdruck) gehören zu einer Activity, die vorn steht.
     * Ohne Anmeldung suchte der Kern das Hauptfenster, das es hier nicht gibt.
     */
    fun vordergrund(activity: Activity?) {
        if (!geladen) return
        try {
            aktivitaet(activity)
        } catch (e: Throwable) {
            // Ohne Kern kein Dialog — dann bleibt es beim Weg über die App.
        }
    }

    /** Ist die Datenbank zu (oder die App gar nicht gestartet)? */
    fun gesperrt(antwort: JSONObject): Boolean =
        antwort.optString("status") in setOf("zu", "aus")

    /** Läuft der Kern überhaupt? Ohne ihn geht auch kein Entsperren. */
    fun aus(antwort: JSONObject): Boolean = antwort.optString("status") == "aus"

    /**
     * Holt die App nach vorn — wenn sich etwas nur dort erledigen lässt,
     * etwa weil noch keine Datenbank ausgewählt ist. Die App bleibt offen;
     * danach das Feld erneut antippen.
     *
     * Läuft die App bloß nicht, ist das nicht der Weg: Dafür startet
     * [de.wuefl.wkeepass.system.Kaltstart] sie nur kurz.
     */
    fun appOeffnen(context: Context) {
        val start = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        start.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(start)
        Toast.makeText(
            context,
            "In ${name(context)} erledigen — dann erneut antippen.",
            Toast.LENGTH_LONG,
        ).show()
    }

    /**
     * Wie die App hier heißt.
     *
     * Die Debug-Fassung heißt „WKeePass-Debug" (`src/debug/res/values/strings.xml`)
     * und tritt in fremden Apps und den Android-Einstellungen unter diesem Namen
     * auf, damit sie sich von der Release-Fassung unterscheiden lässt.
     */
    fun name(context: Context): String = context.getString(R.string.app_name)
}
