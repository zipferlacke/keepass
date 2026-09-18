package de.wuefl.wkeepass.sicherheit

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal

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

    /** Ruft `weiter(true)` nach bestandener Prüfung, sonst `weiter(false)`. */
    fun fragen(activity: Activity, titel: String, weiter: (Boolean) -> Unit) {
        // Vor Android 11 lässt sich die Displaysperre nicht als Ausweg
        // anbieten; dort genügt die offene Datenbank.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            weiter(true)
            return
        }

        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(titel)
            .setSubtitle("WKeePass")
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL)
            .build()

        prompt.authenticate(
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = weiter(true)
                override fun onAuthenticationError(code: Int, meldung: CharSequence) = weiter(false)
            },
        )
    }
}
