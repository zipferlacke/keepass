//! Der eine Weg von Rust zur Java-Seite von Android.
//!
//! # Warum alles hier durchläuft
//!
//! Wirft Java während eines JNI-Aufrufs eine Ausnahme, liefert `jni` einen
//! Fehler zurück — die Ausnahme selbst bleibt aber **hängen**. Der nächste
//! JNI-Aufruf auf diesem Faden, oder die Rückkehr nach Java, bricht dann den
//! ganzen Prozess ab. Kein Absturz mit Meldung, die App ist einfach weg.
//!
//! Genau das ist beim Öffnen vorhandener Datenbanken passiert:
//! `takePersistableUriPermission` wirft bei manchen Dateien eine
//! `SecurityException`, das `?` sprang heraus, bevor jemand aufräumte.
//!
//! Deshalb räumt [`mit_java`] nach **jedem** Aufruf auf, egal wie er
//! ausging. Wer JNI braucht, nimmt diese Funktion und vergisst das Thema.

use std::sync::Mutex;

use jni::objects::{GlobalRef, JObject};
use jni::JNIEnv;
use tao::platform::android::prelude::main_android_context;

/// Die Activity, die gerade vorn steht — sofern es nicht die des Fensters ist.
///
/// Autofill und Passkeys laufen in eigenen Activities über einer **fremden**
/// App; das Hauptfenster ist dabei oft gar nicht da. Ein Systemdialog
/// (`BiometricPrompt`) gehört aber zu einer Activity, die auch wirklich
/// sichtbar ist. Die Dienste melden sich deshalb hier an und wieder ab.
fn vordergrund() -> &'static Mutex<Option<GlobalRef>> {
    static AKTUELL: std::sync::OnceLock<Mutex<Option<GlobalRef>>> = std::sync::OnceLock::new();
    AKTUELL.get_or_init(|| Mutex::new(None))
}

/// Meldet die sichtbare Activity an; `None` meldet sie wieder ab.
pub fn setze_vordergrund(activity: Option<GlobalRef>) {
    if let Ok(mut aktuell) = vordergrund().lock() {
        *aktuell = activity;
    }
}

/// Hängt den Faden an die Java-Umgebung, reicht die Activity herein und
/// räumt hinterher eine offene Ausnahme ab — ins Protokoll, nicht ins Nichts.
pub fn mit_java<T>(
    f: impl FnOnce(&mut JNIEnv, &JObject) -> Result<T, jni::errors::Error>,
) -> Result<T, String> {
    let ctx = main_android_context().ok_or("Die Anwendung läuft noch nicht.")?;

    let vm = unsafe { jni::JavaVM::from_raw(ctx.java_vm.cast()) }
        .map_err(|e| format!("Keine Java-Umgebung: {e}"))?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("Faden nicht angehängt: {e}"))?;

    let fenster = unsafe { JObject::from_raw(ctx.context_jobject.cast()) };
    let dienst = vordergrund().lock().ok().and_then(|a| a.clone());
    let activity = dienst.as_ref().map_or(&fenster, |a| a.as_obj());

    let ergebnis = f(&mut env, activity);
    let ausnahme = abraeumen(&mut env);

    match (ergebnis, ausnahme) {
        (Ok(wert), _) => Ok(wert),
        (Err(_), Some(text)) => Err(text),
        (Err(e), None) => Err(e.to_string()),
    }
}

/// Holt eine hängende Ausnahme ab und gibt ihren Text zurück.
///
/// Auch für JNI-Einstiegspunkte, die Java selbst aufruft (`autofill.rs`,
/// `passkey_android.rs`): Dort gibt es keine Activity aus tao, aufräumen
/// muss man trotzdem.
pub fn abraeumen(env: &mut JNIEnv) -> Option<String> {
    if !env.exception_check().unwrap_or(false) {
        return None;
    }
    let ausnahme = env.exception_occurred().ok();
    let _ = env.exception_clear();

    let text = ausnahme.and_then(|a| {
        let text = env
            .call_method(&a, "toString", "()Ljava/lang/String;", &[])
            .ok()?
            .l()
            .ok()?;
        let text: String = env.get_string(&text.into()).ok()?.into();
        // Auch `toString` könnte werfen — dann eben ohne Text.
        let _ = env.exception_clear();
        Some(text)
    });

    let text = text.unwrap_or_else(|| "Unbekannter Java-Fehler".into());
    eprintln!("[java] {text}");
    Some(text)
}

/// Lädt eine **unserer** Klassen.
///
/// `FindClass` — und damit jedes `call_static_method("de/wuefl/…")` — sucht
/// auf einem Faden, den Rust angehängt hat, nur in den Systemklassen. Die
/// App-Klassen kennt dort nur der ClassLoader der Activity; also über ihn.
/// `name` in Java-Schreibweise mit Punkten.
pub fn klasse<'a>(
    env: &mut JNIEnv<'a>,
    activity: &JObject,
    name: &str,
) -> Result<jni::objects::JClass<'a>, jni::errors::Error> {
    use jni::objects::JValue;

    let lader = env
        .call_method(activity, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;
    let name = env.new_string(name)?;
    let klasse = env
        .call_method(
            lader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name.into())],
        )?
        .l()?;
    Ok(klasse.into())
}
