package de.wuefl.wkeepass.system

import android.app.Activity
import android.content.Context

/**
 * Zurück dorthin, wo man herkam — nach dem Entsperren in der App.
 *
 * Läuft WKeePass gar nicht, können Autofill und Passkeys nicht selbst
 * entsperren: Ohne die App gibt es im Prozess keinen fertigen Kern (siehe
 * `android_services.rs`, Status `"aus"`). Dann geht die App auf
 * ([de.wuefl.wkeepass.kern.Kern.appOeffnen]). Damit man danach nicht von
 * Hand zurückwechseln muss, merkt sich [merken] den Ausflug, und
 * [nachEntsperren] schickt die App nach dem Entsperren wieder nach hinten.
 * Android zeigt dann die App, in der man das Feld angetippt hatte — einmal
 * erneut antippen, und es wird ausgefüllt.
 *
 * Die Vormerkung gilt nur kurz: Wer erst eine Viertelstunde später
 * entsperrt, will in der App bleiben.
 */
object Rueckkehr {

    private const val DATEI = "wkeepass_rueckkehr"
    private const val SCHLUESSEL = "bis"
    private const val FRIST_MS = 5 * 60 * 1000L

    /** Vor dem Öffnen der App: nach dem Entsperren zurück. */
    @JvmStatic
    fun merken(context: Context) {
        context.getSharedPreferences(DATEI, Context.MODE_PRIVATE).edit()
            .putLong(SCHLUESSEL, System.currentTimeMillis() + FRIST_MS)
            .apply()
    }

    /**
     * Nach dem Entsperren, gerufen aus Rust (`system.rs`): Stand ein Ausflug
     * an, geht die App nach hinten. `true`, wenn das geschah.
     */
    @JvmStatic
    fun nachEntsperren(activity: Activity): Boolean {
        val prefs = activity.getSharedPreferences(DATEI, Context.MODE_PRIVATE)
        val bis = prefs.getLong(SCHLUESSEL, 0L)
        if (bis == 0L) return false
        prefs.edit().remove(SCHLUESSEL).apply()
        if (System.currentTimeMillis() > bis) return false
        return activity.moveTaskToBack(true)
    }
}
