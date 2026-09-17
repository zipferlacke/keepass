package de.wuefl.wkeepass.sicherheit

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Ein Schlüssel im Android-Keystore, den nur der Fingerabdruck freigibt.
 *
 * ## Warum das nicht in Rust steht
 *
 * Der Rest der App redet über JNI mit Android, ohne eine Zeile Kotlin.
 * Hier geht das nicht: `BiometricPrompt.authenticate` verlangt eine
 * **Unterklasse** von `AuthenticationCallback`. Eine abstrakte Java-Klasse
 * lässt sich von außen nicht ableiten — weder über JNI noch über einen
 * Proxy, den es nur für Schnittstellen gibt. Also eine Klasse, und die muss
 * mitübersetzt werden.
 *
 * ## Was hier passiert
 *
 * ```text
 * HMAC-Schlüssel im Keystore  ──setUserAuthenticationRequired──┐
 *                                                              │
 * Finger  →  BiometricPrompt  →  Chip gibt den Schlüssel frei ─┘
 *                                       │
 *                             Mac.doFinal(Zufallswert)  →  32 Byte
 * ```
 *
 * Entscheidend ist, **wer** entscheidet: nicht diese App, sondern der
 * Sicherheitschip. Ohne Finger rechnet der Mac nicht, und ohne den Mac gibt
 * es die 32 Byte nicht, mit denen das Master-Passwort versiegelt ist. Wer
 * die App-Daten kopiert, hat nichts davon — der Schlüssel verlässt den Chip
 * nie.
 *
 * Derselbe Zufallswert ergibt auf demselben Gerät immer dieselben 32 Byte;
 * HMAC ist berechenbar, anders als eine Verschlüsselung mit Zufalls-IV.
 * Genau das braucht `seal.rs`, und genau so macht es die Windows-Seite mit
 * der Hello-Signatur.
 *
 * ## Wann der Schlüssel verschwindet
 *
 * Wird ein Fingerabdruck hinzugefügt oder entfernt, erklärt Android den
 * Schlüssel für ungültig (`setInvalidatedByBiometricEnrollment`). Wir legen
 * dann stillschweigend einen neuen an: Das Siegel geht danach nicht mehr
 * auf, die App meldet das und bittet um das Master-Passwort — was genau
 * richtig ist, denn ein fremder Finger darf die Datenbank nicht erben.
 */
object Geraeteschluessel {

    /** Name des Schlüssels im Keystore. Gehört dieser App und diesem Gerät. */
    private const val ALIAS = "de.wuefl.wkeepass.geraeteschluessel"
    private const val KEYSTORE = "AndroidKeyStore"

    /** So lange darf der Dialog offen stehen, bevor wir aufgeben. */
    private const val WARTEZEIT_SEKUNDEN = 120L

    /** Grund des letzten Fehlschlags — die Rust-Seite holt ihn sich ab. */
    @Volatile
    private var fehler: String = ""

    @JvmStatic
    fun letzterFehler(): String = fehler

    /**
     * Kann dieses Gerät einen biometrisch gebundenen Schlüssel liefern?
     *
     * Verlangt Android 11: Erst dort lässt sich ein Schlüssel gezielt an
     * die **starke** Biometrie binden (`setUserAuthenticationParameters`).
     * Darunter bleibt es beim Weg über PIN und Schlüsselbund.
     *
     * `BIOMETRIC_STRONG` ist Absicht: Nur Sensoren dieser Klasse dürfen
     * Keystore-Schlüssel freigeben. Eine schwache Gesichtserkennung kann
     * das nicht, und ein Knopf, der dann beim Drücken scheitert, wäre
     * schlimmer als keiner.
     */
    @JvmStatic
    fun verfuegbar(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return false
        val manager = context.getSystemService(BiometricManager::class.java) ?: return false
        return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Fragt den Finger ab und rechnet daraus 32 Byte Schlüssel.
     *
     * Leeres Ergebnis heißt Fehlschlag; der Grund steht dann in
     * [letzterFehler]. Ausnahmen bleiben hier — über die JNI-Grenze
     * geworfen wären sie nur schwerer zu lesen.
     */
    @JvmStatic
    fun ableiten(activity: Activity, zufallswert: ByteArray): ByteArray {
        fehler = ""
        if (!verfuegbar(activity)) {
            fehler = "Auf diesem Gerät ist keine geprüfte Biometrie eingerichtet."
            return ByteArray(0)
        }
        return try {
            fragen(activity, mac(), zufallswert)
        } catch (e: Throwable) {
            fehler = e.message ?: e.toString()
            ByteArray(0)
        }
    }

    /** Löscht den Schlüssel — danach ist jedes Siegel darauf wertlos. */
    @JvmStatic
    fun vergessen() {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
        } catch (e: Throwable) {
            fehler = e.message ?: e.toString()
        }
    }

    /**
     * Holt den Schlüssel aus dem Keystore oder legt ihn beim ersten Mal an.
     *
     * `mac.init` ist der Moment, in dem sich ein ungültig gewordener
     * Schlüssel meldet (neuer Fingerabdruck). Dann bleibt nur: wegwerfen
     * und neu anlegen.
     */
    private fun mac(): Mac {
        val mac = Mac.getInstance("HmacSHA256")
        try {
            mac.init(vorhandenerSchluessel() ?: anlegen())
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            vergessen()
            mac.init(anlegen())
        }
        return mac
    }

    private fun vorhandenerSchluessel(): SecretKey? {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return store.getKey(ALIAS, null) as? SecretKey
    }

    /**
     * Legt einen HMAC-Schlüssel an, der ohne frische biometrische Prüfung
     * nichts rechnet.
     *
     * `setUserAuthenticationParameters(0, …)` heißt: für **jede** Benutzung
     * neu prüfen, keine Gnadenfrist von ein paar Sekunden.
     *
     * StrongBox ist der eigene Sicherheitschip (bei Pixel der Titan). Gibt
     * es ihn nicht, tut es die normale vertrauenswürdige Umgebung auch —
     * beides hält den Schlüssel außerhalb dieser App.
     */
    private fun anlegen(): SecretKey {
        fun bauen(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
            generator.init(spec)
            return generator.generateKey()
        }

        return try {
            bauen(true)
        } catch (e: StrongBoxUnavailableException) {
            bauen(false)
        }
    }

    /**
     * Zeigt den Systemdialog und wartet auf das Ergebnis.
     *
     * Der Dialog gehört auf den Hauptfaden, gerufen werden wir aber aus
     * einem Arbeitsfaden von Rust. Also: hinschicken, hier warten. Andersrum
     * wäre es ein Stillstand — deshalb darf diese Methode nie vom
     * Hauptfaden aus aufgerufen werden.
     */
    private fun fragen(activity: Activity, mac: Mac, zufallswert: ByteArray): ByteArray {
        val antwort = ArrayBlockingQueue<Any>(1)
        val abbruch = CancellationSignal()
        val ausfuehrer = activity.mainExecutor

        Handler(Looper.getMainLooper()).post {
            try {
                val prompt = BiometricPrompt.Builder(activity)
                    .setTitle("WKeePass")
                    .setSubtitle("Datenbank entsperren")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    // Bei starker Biometrie verlangt Android einen Ausweg;
                    // unserer ist das Master-Passwort in der App selbst.
                    .setNegativeButton("Abbrechen", ausfuehrer) { _, _ -> abbruch.cancel() }
                    .build()

                prompt.authenticate(
                    BiometricPrompt.CryptoObject(mac),
                    abbruch,
                    ausfuehrer,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            ergebnis: BiometricPrompt.AuthenticationResult
                        ) {
                            val freigegeben = ergebnis.cryptoObject?.mac
                            antwort.offer(freigegeben ?: "Der Schlüssel wurde nicht freigegeben.")
                        }

                        override fun onAuthenticationError(code: Int, meldung: CharSequence) {
                            antwort.offer(meldung.toString())
                        }
                    },
                )
            } catch (e: Throwable) {
                antwort.offer(e.message ?: e.toString())
            }
        }

        val ergebnis = antwort.poll(WARTEZEIT_SEKUNDEN, TimeUnit.SECONDS)
        if (ergebnis == null) {
            abbruch.cancel()
            throw IllegalStateException("Zeitüberschreitung bei der biometrischen Prüfung.")
        }
        // Der Mac aus dem CryptoObject ist derselbe, nur eben freigeschaltet.
        if (ergebnis is Mac) return ergebnis.doFinal(zufallswert)
        throw IllegalStateException(ergebnis.toString())
    }
}
