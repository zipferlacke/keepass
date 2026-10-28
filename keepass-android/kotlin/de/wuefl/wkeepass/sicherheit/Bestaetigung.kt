package de.wuefl.wkeepass.sicherheit

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.SystemClock
import de.wuefl.wkeepass.kern.Kern

/**
 * „Bist du es?" — vor dem Herausgeben eines Passkeys.
 *
 * Ein Passkey meldet der Gegenstelle ausdrücklich, dass der Nutzer geprüft
 * wurde (Flag UV in der authenticatorData). Das darf nicht gelogen sein,
 * also fragen wir wirklich: Finger, Gesicht oder die Displaysperre.
 *
 * Anders als [Geraeteschluessel] ohne Schlüssel — hier geht es um den
 * Nachweis, die Datenbank ist ja schon offen.
 */
object Bestaetigung {

    /**
     * Wie lange ein Nachweis gilt — wie `browser.graceSeconds` am Rechner.
     * Wer gerade entsperrt hat, um einen Passkey zu nutzen, wurde sonst
     * gleich darauf ein zweites Mal nach dem Finger gefragt.
     */
    private const val FRIST_MS = 60_000L

    @Volatile
    private var zuletzt = 0L

    /** Merkt sich einen bestandenen Nachweis — auch das Entsperren ist einer. */
    fun bestaetigt() {
        zuletzt = SystemClock.elapsedRealtime()
    }

    private fun frisch() = zuletzt != 0L && SystemClock.elapsedRealtime() - zuletzt < FRIST_MS

    /** Ruft `weiter(true)` nach bestandener Prüfung, sonst `weiter(false)`. */
    fun fragen(activity: Activity, titel: String, weiter: (Boolean) -> Unit) {
        if (frisch()) {
            weiter(true)
            return
        }

        // Vor Android 11 lässt sich die Displaysperre nicht als Ausweg
        // anbieten; dort genügt die offene Datenbank.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            weiter(true)
            return
        }

        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(titel)
            .setSubtitle(Kern.name(activity))
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL)
            .build()

        prompt.authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    bestaetigt()
                    weiter(true)
                }
                override fun onAuthenticationError(code: Int, meldung: CharSequence) = weiter(false)
            },
        )
    }
}
