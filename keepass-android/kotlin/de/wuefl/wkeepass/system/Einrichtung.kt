package de.wuefl.wkeepass.system

import android.Manifest
import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import de.wuefl.wkeepass.passkey.WKeePassCredentialService
import org.json.JSONObject

/**
 * Was die App auf Android eingerichtet haben möchte — und der Weg dorthin.
 *
 * Drei Dinge, die nur der Nutzer freigeben kann:
 *
 * ```text
 * autofill   WKeePass als Passwortmanager (Autofill-Dienst)
 * passkeys   WKeePass als Passkey-Anbieter (ab Android 14)
 * kamera     für den QR-Scanner beim Einrichten von TOTP
 * ```
 *
 * [status] sagt, was schon steht; [oeffnen] springt in genau die
 * Systemeinstellung, in der man es ändert. Gerufen aus Rust
 * (`system.rs`), für die Einstellungen und die Begrüßung der Oberfläche.
 */
object Einrichtung {

    private const val KAMERA_ANFRAGE = 4711

    @JvmStatic
    fun status(activity: Activity): String {
        val autofill = activity.getSystemService(AutofillManager::class.java)
        val autofillMoeglich = autofill?.isAutofillSupported == true
        val autofillAktiv = autofillMoeglich && autofill.hasEnabledAutofillServices()

        val passkeyMoeglich = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        val passkeyAktiv = passkeyMoeglich && try {
            activity.getSystemService(android.credentials.CredentialManager::class.java)
                ?.isEnabledCredentialProviderService(
                    ComponentName(activity, WKeePassCredentialService::class.java)
                ) == true
        } catch (e: Throwable) {
            false
        }

        val kamera = activity.checkSelfPermission(Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED

        return JSONObject()
            .put("autofill", JSONObject().put("moeglich", autofillMoeglich).put("aktiv", autofillAktiv))
            .put("passkeys", JSONObject().put("moeglich", passkeyMoeglich).put("aktiv", passkeyAktiv))
            .put("kamera", JSONObject().put("moeglich", true).put("aktiv", kamera)
                // Zweimal abgelehnt fragt Android nicht mehr — dann bleibt
                // nur der Weg über die App-Einstellungen.
                .put("gesperrt", !kamera && !activity.shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)
                    && gefragt(activity)))
            .toString()
    }

    /** Springt in die passende Einstellung. `false`: Das ging nicht. */
    @JvmStatic
    fun oeffnen(activity: Activity, was: String): Boolean {
        val paket = Uri.parse("package:${activity.packageName}")
        val ziel: Intent? = when (was) {
            // Der Systemdialog „WKeePass als Autofill-Dienst verwenden?"
            "autofill" -> Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(paket)
            // Passwörter, Passkeys & Konten. Eine öffentliche Konstante gibt
            // es dafür erst ab Android 14, und auch dort nur als Text.
            "passkeys" -> Intent("android.settings.CREDENTIAL_PROVIDER").setData(paket)
            "app" -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(paket)
            "kamera" -> {
                if (gefragt(activity) && !activity.shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) {
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(paket)
                } else {
                    merkeGefragt(activity)
                    activity.runOnUiThread {
                        activity.requestPermissions(arrayOf(Manifest.permission.CAMERA), KAMERA_ANFRAGE)
                    }
                    null
                }
            }
            else -> return false
        }
        ziel ?: return true

        return try {
            activity.runOnUiThread {
                try {
                    activity.startActivity(ziel)
                } catch (e: Throwable) {
                    // Manche Hersteller kennen die Passkey-Seite nicht —
                    // dann wenigstens in die allgemeinen Einstellungen.
                    activity.startActivity(Intent(Settings.ACTION_SETTINGS))
                }
            }
            true
        } catch (e: Throwable) {
            false
        }
    }

    /* Ob die Kamera schon einmal angefragt wurde. Android verrät das nicht,
       und ohne das wäre „nie gefragt" nicht von „für immer abgelehnt" zu
       unterscheiden — beides meldet `shouldShowRequestPermissionRationale`
       mit `false`. */

    private fun gefragt(activity: Activity) =
        activity.getSharedPreferences("wkeepass-einrichtung", 0).getBoolean("kamera-gefragt", false)

    private fun merkeGefragt(activity: Activity) =
        activity.getSharedPreferences("wkeepass-einrichtung", 0).edit().putBoolean("kamera-gefragt", true).apply()
}
