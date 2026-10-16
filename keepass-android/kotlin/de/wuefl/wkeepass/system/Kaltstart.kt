package de.wuefl.wkeepass.system

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import de.wuefl.wkeepass.kern.Kern

/**
 * Startet die App, wenn sie gar nicht läuft — und nur so lange, bis der Kern
 * steht.
 *
 * Autofill und Passkeys entsperren selbst, im Blatt über der fremden App.
 * Das geht aber nur, wenn es im Prozess einen Kern gibt: Einstellungen,
 * Schlüsselbund und Dateizugriff richtet Tauri ein, und Tauri startet erst
 * mit der Activity der App (Status `"aus"`, siehe `android_services.rs`).
 *
 * Also wird die App gestartet, aber nicht benutzt: Sobald der Kern
 * antwortet, geht sie sofort wieder nach hinten. Vorn steht dann wieder die
 * fremde App mit unserem Blatt darüber, und das Blatt macht weiter — mit
 * PIN, Biometrie oder Master-Passwort wie sonst auch. Kein zweites Antippen.
 *
 * Kommt der Kern nicht rechtzeitig, bleibt die App offen; dort lässt sich
 * wie gewohnt entsperren.
 */
object Kaltstart {

    /** So lange darf der Start dauern. */
    private const val FRIST_MS = 20_000L
    private const val TAKT_MS = 100L

    /**
     * Startet die App für `blatt` und ruft `dann(true)`, sobald der Kern läuft
     * und das Blatt wieder vorn steht. `dann(false)`, wenn das nicht klappt.
     */
    fun starten(blatt: Activity, dann: (Boolean) -> Unit) {
        val start = blatt.packageManager.getLaunchIntentForPackage(blatt.packageName)
            ?: return dann(false)
        val app = blatt.application
        val haupt = Handler(Looper.getMainLooper())

        var fenster: Activity? = null   // die gestartete App
        var blattVorn = false
        var kernDa = false
        var fertig = false

        lateinit var beobachter: Application.ActivityLifecycleCallbacks
        fun ende(ok: Boolean) {
            if (fertig) return
            fertig = true
            app.unregisterActivityLifecycleCallbacks(beobachter)
            dann(ok)
        }

        beobachter = object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(a: Activity, b: Bundle?) {
                if (a !== blatt && a.componentName == start.component) fenster = a
            }
            override fun onActivityResumed(a: Activity) {
                if (a !== blatt) return
                blattVorn = true
                // Erst weiter, wenn der Kern steht — wer vorher von Hand
                // zurückwechselt, wartet eben noch kurz.
                if (kernDa) ende(true)
            }
            override fun onActivityPaused(a: Activity) {
                if (a === blatt) blattVorn = false
            }
            override fun onActivityDestroyed(a: Activity) {
                // Das Blatt ist weg — niemand mehr, für den es weitergeht.
                if (a === blatt && !fertig) {
                    fertig = true
                    app.unregisterActivityLifecycleCallbacks(beobachter)
                }
            }
            override fun onActivityStarted(a: Activity) {}
            override fun onActivityStopped(a: Activity) {}
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
        }
        app.registerActivityLifecycleCallbacks(beobachter)

        start.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        blatt.startActivity(start)
        Toast.makeText(blatt, "${Kern.name(blatt)} startet …", Toast.LENGTH_SHORT).show()

        // Auf den Kern warten — nicht auf dem Hauptfaden, der muss die App
        // derweil aufbauen.
        Thread {
            val bis = System.currentTimeMillis() + FRIST_MS
            var laeuft = false
            while (!laeuft && System.currentTimeMillis() < bis) {
                Thread.sleep(TAKT_MS)
                laeuft = !Kern.aus(Kern.frage { Kern.status() })
            }
            haupt.post {
                if (fertig) return@post
                if (!laeuft) return@post ende(false)
                kernDa = true
                // Die App hat ihren Dienst getan: zurück dorthin, wo man
                // herkam. Android holt die Aufgabe darunter nach vorn —
                // die fremde App samt Blatt.
                fenster?.moveTaskToBack(true)
                if (blattVorn) ende(true)
            }
        }.start()
    }
}
