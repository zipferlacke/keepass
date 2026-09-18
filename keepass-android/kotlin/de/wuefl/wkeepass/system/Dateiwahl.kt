package de.wuefl.wkeepass.system

import android.app.Activity
import android.content.Intent
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Datenbank auswählen — mit **dauerhafter** Erlaubnis.
 *
 * Der Dateidialog von Tauri fragt mit `ACTION_GET_CONTENT`. Android gibt
 * darauf nur eine Erlaubnis bis zum Ende der App: Nach dem nächsten Start
 * war eine Datei aus Nextcloud oder Drive nicht mehr lesbar.
 *
 * `ACTION_OPEN_DOCUMENT` zeigt dieselbe Auswahl des Systems, liefert aber
 * eine Adresse, deren Lese- und Schreibrecht sich die App mit
 * `takePersistableUriPermission` für immer sichern kann.
 *
 * Aufgerufen aus Rust (system.rs) auf einem eigenen Faden, der hier wartet,
 * bis gewählt oder abgebrochen ist.
 */
object Dateiwahl {
    private const val TAG = "WKeePass"

    @JvmStatic
    fun waehlen(activity: Activity): String? {
        val ergebnis = ArrayBlockingQueue<String>(1)

        activity.runOnUiThread {
            val act = activity as? ComponentActivity
            if (act == null) {
                ergebnis.offer("")
                return@runOnUiThread
            }
            var launcher: ActivityResultLauncher<Array<String>>? = null
            launcher = act.activityResultRegistry.register(
                "wkeepass-dateiwahl-${System.nanoTime()}",
                ActivityResultContracts.OpenDocument()
            ) { uri ->
                if (uri != null) sichern(act, uri)
                ergebnis.offer(uri?.toString() ?: "")
                launcher?.unregister()
            }
            // KDBX hat keinen eigenen MIME-Typ — Anbieter melden sie als
            // application/octet-stream oder gar nicht. Also alles zeigen.
            launcher.launch(arrayOf("*/*"))
        }

        val uri = ergebnis.poll(30, TimeUnit.MINUTES) ?: ""
        return uri.ifEmpty { null }
    }

    /** Lesen und Schreiben dauerhaft — wo der Anbieter kein Schreiben erlaubt, wenigstens Lesen. */
    private fun sichern(activity: Activity, uri: android.net.Uri) {
        val lesen = Intent.FLAG_GRANT_READ_URI_PERMISSION
        val schreiben = Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        try {
            activity.contentResolver.takePersistableUriPermission(uri, lesen or schreiben)
        } catch (e: SecurityException) {
            Log.w(TAG, "Schreibrecht nicht dauerhaft: ${e.message}")
            try {
                activity.contentResolver.takePersistableUriPermission(uri, lesen)
            } catch (e2: SecurityException) {
                Log.w(TAG, "Leserecht nicht dauerhaft: ${e2.message}")
            }
        }
    }
}
