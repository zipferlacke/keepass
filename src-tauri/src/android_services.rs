//! Der Kern für Autofill und Passkeys auf Android.
//!
//! # Wer hier anruft
//!
//! Nicht die Oberfläche, sondern Android selbst — über unsere Kotlin-Klassen
//! (`keepass-android/kotlin/de/wuefl/wkeepass/kern/Kern.kt`). Der
//! Autofill-Dienst und der Passkey-Anbieter laufen, während der Nutzer in
//! einer **fremden** App steht. Sie fragen hier nach, was die offene
//! Datenbank für diese App oder Seite hergibt.
//!
//! # Was hier bewusst nicht passiert: entsperren
//!
//! Ist die Datenbank zu, antwortet dieses Modul nur „zu", und die Kotlin-Seite
//! holt die App nach vorn. Entsperrt wird dort, auf den bekannten Wegen —
//! Master-Passwort, PIN, Fingerabdruck. Ein zweiter Entsperrweg im Dienst
//! wäre eine zweite Tür, die man genauso gut sichern müsste.
//!
//! # Das Format
//!
//! Jede Funktion gibt JSON als Text zurück. Ein Fehler steht unter
//! `"fehler"`, nie als Java-Ausnahme — die wäre über die Grenze hinweg nur
//! schwerer zu lesen, und eine vergessene riss früher den Prozess mit.
//!
//! Kein Panic darf die Grenze überqueren: Jeder Einstieg läuft durch
//! [`antworte`], das ihn auffängt.

use std::panic::AssertUnwindSafe;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;
use serde_json::{json, Value};
use tauri::{Emitter, Manager};

use crate::matching::{entry_urls, host_of, match_score};
use crate::state::VaultState;
use crate::Vault;

/// Präfix, unter dem Apps an Einträgen hängen — wie bei KeePassDX.
const APP_PREFIX: &str = "androidapp://";

/* =========================================================
   Einstiege — die Namen legt die Kotlin-Klasse fest
   ========================================================= */

/// `"offen"`, `"zu"` oder `"aus"` (App-Kern läuft gar nicht).
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_status<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
) -> jstring {
    antworte(&mut env, |_| Ok(json!({ "status": status() })))
}

/// Einträge für eine App oder Seite.
///
/// Passt etwas, kommt nur das (`"passend": true`). Passt nichts, kommt die
/// ganze Liste — dann wählt der Nutzer selbst, und `zugang` kann sich die
/// App am gewählten Eintrag merken.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_treffer<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    paket: JString<'l>,
    web: JString<'l>,
) -> jstring {
    let paket = text(&mut env, &paket);
    let web = text(&mut env, &web);
    antworte(&mut env, move |_| treffer(&paket, &web))
}

/// Benutzername und Passwort eines Eintrags.
///
/// `merken`: Die App kam bisher nicht vor — ihr Paketname wird als
/// `androidapp://…` an den Eintrag geschrieben, damit sie beim nächsten Mal
/// direkt passt.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_zugang<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    id: JString<'l>,
    paket: JString<'l>,
    merken: jboolean,
) -> jstring {
    let id = text(&mut env, &id);
    let paket = text(&mut env, &paket);
    antworte(&mut env, move |_| zugang(&id, &paket, merken != 0))
}

/// Legt aus einem abgeschickten Formular einen neuen Eintrag an.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_speichern<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    paket: JString<'l>,
    web: JString<'l>,
    benutzer: JString<'l>,
    passwort: JString<'l>,
) -> jstring {
    let paket = text(&mut env, &paket);
    let web = text(&mut env, &web);
    let benutzer = text(&mut env, &benutzer);
    let passwort = zeroize::Zeroizing::new(text(&mut env, &passwort));
    antworte(&mut env, move |_| speichern(&paket, &web, &benutzer, &passwort))
}

/// Passkeys einer Gegenstelle: `[{credentialId, userName}]`.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_passkeys<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    rp_id: JString<'l>,
) -> jstring {
    let rp_id = text(&mut env, &rp_id);
    antworte(&mut env, move |_| {
        let app = app()?;
        let state = app.state::<Vault>();
        let vault = offen(&state)?;
        let liste = crate::passkey::list_in(&vault, Some(&rp_id))?;
        Ok(json!({ "passkeys": liste }))
    })
}

/// Legt einen Passkey an. Eingabe und Ausgabe im JSON-Format von WebAuthn,
/// so wie Android es durchreicht.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_passkeyAnlegen<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    anfrage: JString<'l>,
    herkunft: JString<'l>,
    client_hash: JString<'l>,
) -> jstring {
    let anfrage = text(&mut env, &anfrage);
    let herkunft = text(&mut env, &herkunft);
    let client_hash = text(&mut env, &client_hash);
    antworte(&mut env, move |_| passkey_anlegen(&anfrage, &herkunft, &client_hash))
}

/// Meldet mit einem Passkey an.
#[no_mangle]
pub extern "system" fn Java_de_wuefl_wkeepass_kern_Kern_passkeyAnmelden<'l>(
    mut env: JNIEnv<'l>,
    _cls: JClass<'l>,
    anfrage: JString<'l>,
    credential_id: JString<'l>,
    herkunft: JString<'l>,
    client_hash: JString<'l>,
) -> jstring {
    let anfrage = text(&mut env, &anfrage);
    let credential_id = text(&mut env, &credential_id);
    let herkunft = text(&mut env, &herkunft);
    let client_hash = text(&mut env, &client_hash);
    antworte(&mut env, move |_| passkey_anmelden(&anfrage, &credential_id, &herkunft, &client_hash))
}

/* =========================================================
   Autofill
   ========================================================= */

fn status() -> &'static str {
    let Some(app) = crate::app_handle() else { return "aus" };
    let state = app.state::<Vault>();
    let offen = state
        .lock()
        .is_ok_and(|vault| vault.database().is_ok() && !vault.idle_expired());
    if offen { "offen" } else { "zu" }
}

fn treffer(paket: &str, web: &str) -> Result<Value, String> {
    let app = app()?;
    let state = app.state::<Vault>();
    let vault = offen(&state)?;
    let db = vault.database()?;
    let bin = crate::state::recycle_bin(db);

    // Die Webadresse ist die genauere Kennung. Ohne sie bleibt die App.
    let (host, pfad): (String, Vec<String>) = if !web.is_empty() {
        let host = host_of(web).unwrap_or_else(|| web.to_ascii_lowercase());
        (host, Vec::new())
    } else {
        (paket.to_ascii_lowercase(), Vec::new())
    };

    let mut alle = Vec::new();
    let mut passend = Vec::new();

    for entry in db.iter_all_entries() {
        if bin.is_some_and(|b| entry.parent().id() == b) {
            continue;
        }
        // Passkeys haben kein Passwort — in der Auswahl wären sie eine
        // Zeile, die beim Antippen ein leeres Feld hinterlässt.
        if entry.get(crate::passkey::F_ID).is_some() {
            continue;
        }

        let urls = entry_urls(&entry);
        let score = if web.is_empty() {
            // Eine App passt nur über ihren genauen Paketnamen. Ein
            // Teilstück wie bei Rechnernamen gibt es hier nicht:
            // `com.bank` ist nicht die Elternseite von `com.bank.fake`.
            urls.iter()
                .any(|u| u.strip_prefix(APP_PREFIX).is_some_and(|p| p.trim_end_matches('/') == paket))
                .then_some(100)
        } else {
            urls.iter().filter_map(|u| match_score(u, &host, &pfad)).max()
        };

        let zeile = json!({
            "id": entry.id().uuid().to_string(),
            "titel": entry.get_title().unwrap_or_default(),
            "benutzer": entry.get_username().unwrap_or_default(),
            "ordner": crate::state::folder_path(db, entry.parent().id()),
            "passend": score.is_some(),
            "totp": entry.get_raw_otp_value().is_some(),
        });

        match score {
            Some(s) => passend.push((s, zeile)),
            None => alle.push(zeile),
        }
    }

    // Passende zuerst, der genaueste oben; danach der Rest nach Titel —
    // damit man auch an ein Konto kommt, das an der Seite noch nicht hängt.
    passend.sort_by(|a, b| b.0.cmp(&a.0));
    alle.sort_by_key(|z| z["titel"].as_str().unwrap_or_default().to_lowercase());
    let liste: Vec<Value> = passend.into_iter().map(|(_, z)| z).chain(alle).collect();
    Ok(json!({ "status": "offen", "eintraege": liste }))
}

fn zugang(id: &str, paket: &str, merken: bool) -> Result<Value, String> {
    let app = app()?;
    let state = app.state::<Vault>();

    let (antwort, geaendert) = {
        let mut vault = offen(&state)?;
        vault.touch();
        // Für „Inaktive Einträge": benutzt ist benutzt, auch über Autofill.
        let _ = crate::entries::mark_accessed(&mut vault, &[id.to_string()]);
        let db = vault.database_mut()?;

        let entry_id = db
            .iter_all_entries()
            .find(|e| e.id().uuid().to_string() == id)
            .map(|e| e.id())
            .ok_or("Der Eintrag ist nicht mehr da.")?;

        let antwort = {
            let entry = db.entry(entry_id).ok_or("Der Eintrag ist nicht mehr da.")?;
            json!({
                "benutzer": entry.get_username().unwrap_or_default(),
                "passwort": entry.get_password().unwrap_or_default(),
                // Der gerade gültige Code — nach dem Einsetzen landet er in
                // der Zwischenablage, oder direkt im Code-Feld.
                "totp": entry
                    .get_raw_otp_value()
                    .and_then(crate::secrets::current_totp)
                    .unwrap_or_default(),
            })
        };

        let mut geaendert = false;
        if merken && !paket.is_empty() {
            let mut entry = db.entry_mut(entry_id).ok_or("Der Eintrag ist nicht mehr da.")?;
            let schon = entry_urls(&entry.as_ref())
                .iter()
                .any(|u| u.strip_prefix(APP_PREFIX) == Some(paket));
            if !schon {
                let frei = (1..)
                    .map(|n| if n == 1 { "KP_ADDITIONAL_URL".to_string() } else { format!("KP_ADDITIONAL_URL_{n}") })
                    .find(|name| entry.get(name).is_none())
                    .expect("unendliche Folge");
                let mut entry = entry.track_changes();
                entry.set_unprotected(frei, format!("{APP_PREFIX}{paket}"));
                geaendert = true;
            }
        }
        (antwort, geaendert)
    };

    let _ = app.emit("entries-used", [id]);
    // Beim Anmelden ist die Seite erreichbar — Icon holen, falls es fehlt.
    crate::favicon::im_hintergrund(&app, vec![id.to_string()], false);
    if geaendert {
        speichern_im_hintergrund(&app);
    // Neuer Zugang: Welcher Eintrag es ist, weiß `eintragen` — einfacher,
    // alle nachzuziehen, denen noch ein Icon fehlt.
    crate::favicon::im_hintergrund(&app, Vec::new(), false);
    }
    Ok(antwort)
}

fn speichern(paket: &str, web: &str, benutzer: &str, passwort: &str) -> Result<Value, String> {
    if passwort.is_empty() {
        return Err("Ohne Passwort gibt es nichts zu speichern.".into());
    }
    let neu = Vorgemerkt {
        paket: paket.to_string(),
        web: web.to_string(),
        benutzer: benutzer.to_string(),
        passwort: zeroize::Zeroizing::new(passwort.to_string()),
    };

    // Datenbank zu: vormerken und nach dem Entsperren eintragen. Sonst
    // wäre ein gerade angelegtes Konto nur noch im Kopf des Nutzers.
    let Some(app) = crate::app_handle().cloned() else {
        vormerken(neu);
        return Ok(json!({ "status": "vorgemerkt" }));
    };
    let state = app.state::<Vault>();
    let geaendert = match offen(&state) {
        Ok(mut vault) => eintragen(&mut vault, &neu)?,
        Err(_) => {
            vormerken(neu);
            return Ok(json!({ "status": "vorgemerkt" }));
        }
    };

    speichern_im_hintergrund(&app);
    Ok(json!({ "ok": true, "aktualisiert": geaendert }))
}

/// Ein Zugang, der auf das Entsperren wartet. Nur im Arbeitsspeicher —
/// auf die Platte kommt ein Passwort bei uns nur verschlüsselt.
struct Vorgemerkt {
    paket: String,
    web: String,
    benutzer: String,
    passwort: zeroize::Zeroizing<String>,
}

static VORGEMERKT: std::sync::Mutex<Vec<Vorgemerkt>> = std::sync::Mutex::new(Vec::new());

fn vormerken(zugang: Vorgemerkt) {
    if let Ok(mut liste) = VORGEMERKT.lock() {
        liste.push(zugang);
    }
}

/// Nach dem Entsperren: Was während der Sperre gespeichert werden sollte,
/// kommt jetzt in die Datenbank. Aufgerufen aus `database::vault_unlock`.
pub fn nach_entsperren(app: &tauri::AppHandle) {
    let wartend: Vec<Vorgemerkt> = match VORGEMERKT.lock() {
        Ok(mut liste) => std::mem::take(&mut *liste),
        Err(_) => return,
    };
    if wartend.is_empty() {
        return;
    }

    let state = app.state::<Vault>();
    let Ok(mut vault) = offen(&state) else { return };
    let mut zahl = 0;
    for zugang in &wartend {
        if eintragen(&mut vault, zugang).is_ok() {
            zahl += 1;
        }
    }
    drop(vault);

    if zahl > 0 {
        let _ = app.emit("autofill-saved", zahl);
        speichern_im_hintergrund(app);
    }
}

/// Trägt einen Zugang ein. Gibt es für dieselbe Seite oder App schon einen
/// Eintrag mit diesem Benutzernamen, bekommt der das neue Passwort — das
/// alte bleibt im Verlauf. `true` heißt: aktualisiert statt neu.
fn eintragen(vault: &mut VaultState, zugang: &Vorgemerkt) -> Result<bool, String> {
    let (titel, adresse, host) = if !zugang.web.is_empty() {
        let host = host_of(&zugang.web).unwrap_or_else(|| zugang.web.to_ascii_lowercase());
        (host.clone(), format!("https://{host}"), host)
    } else {
        // `com.nextcloud.client` → „nextcloud" als Titel: das sprechendste
        // Stück, meist der Herstellername.
        let titel = zugang
            .paket
            .split('.')
            .find(|t| !matches!(*t, "com" | "de" | "org" | "net" | "android" | "app" | "client" | "mobile"))
            .unwrap_or(&zugang.paket)
            .to_string();
        (titel, format!("{APP_PREFIX}{}", zugang.paket), zugang.paket.clone())
    };

    let db = vault.database_mut()?;
    let bin = crate::state::recycle_bin(db);

    let vorhanden = (!zugang.benutzer.is_empty())
        .then(|| {
            db.iter_all_entries()
                .filter(|e| !bin.is_some_and(|b| e.parent().id() == b))
                .filter(|e| e.get_username() == Some(zugang.benutzer.as_str()))
                .find(|e| {
                    entry_urls(e).iter().any(|u| {
                        if zugang.web.is_empty() {
                            u.strip_prefix(APP_PREFIX) == Some(zugang.paket.as_str())
                        } else {
                            match_score(u, &host, &[]).is_some_and(|s| s >= 100)
                        }
                    })
                })
                .map(|e| e.id())
        })
        .flatten();

    if let Some(id) = vorhanden {
        let mut entry = db.entry_mut(id).ok_or("Eintrag verschwunden.")?;
        if entry.get_password() == Some(zugang.passwort.as_str()) {
            return Ok(true);
        }
        let mut entry = entry.track_changes();
        entry.set_protected(keepass::db::fields::PASSWORD, zugang.passwort.to_string());
        return Ok(true);
    }

    let root = db.root().id();
    let id = db.group_mut(root).ok_or("Stammordner fehlt.")?.add_entry().id();
    let mut entry = db.entry_mut(id).ok_or("Eintrag verschwunden.")?;
    entry.set_unprotected(keepass::db::fields::TITLE, titel);
    entry.set_unprotected(keepass::db::fields::USERNAME, zugang.benutzer.clone());
    entry.set_protected(keepass::db::fields::PASSWORD, zugang.passwort.to_string());
    entry.set_unprotected(keepass::db::fields::URL, adresse);
    entry.times.last_modification = Some(keepass::db::Times::now());
    Ok(false)
}

/* =========================================================
   Passkeys
   ========================================================= */

fn passkey_anlegen(anfrage: &str, herkunft: &str, client_hash: &str) -> Result<Value, String> {
    let anfrage: Value = serde_json::from_str(anfrage).map_err(|e| format!("Anfrage unlesbar: {e}"))?;

    let rp_id = anfrage["rp"]["id"].as_str().ok_or("Die Anfrage nennt keine Gegenstelle.")?;
    let user = &anfrage["user"];
    let request = crate::passkey::CreateRequest {
        rp_id: rp_id.to_string(),
        user_name: user["name"].as_str().unwrap_or_default().to_string(),
        user_display_name: user["displayName"].as_str().map(str::to_string),
        challenge: anfrage["challenge"].as_str().ok_or("Die Anfrage hat keine Challenge.")?.to_string(),
        user_handle: user["id"].as_str().map(str::to_string),
        origin: (!herkunft.is_empty()).then(|| herkunft.to_string()),
    };

    // Nur ES256 können wir. Verlangt die Gegenstelle etwas anderes, ist
    // ein ehrliches Nein besser als ein Schlüssel, den sie ablehnt.
    if let Some(params) = anfrage["pubKeyCredParams"].as_array() {
        if !params.is_empty() && !params.iter().any(|p| p["alg"].as_i64() == Some(-7)) {
            return Err("Die Gegenstelle verlangt ein Verfahren, das WKeePass nicht kann.".into());
        }
    }

    let app = app()?;
    let state = app.state::<Vault>();
    let created = {
        let mut vault = offen(&state)?;

        // Schon einer da, den die Gegenstelle ausschließt? Dann doppelt
        // anzulegen hieße, einen zweiten Zugang neben den ersten zu setzen.
        if let Some(ausschluss) = anfrage["excludeCredentials"].as_array() {
            let vorhanden = crate::passkey::list_in(&vault, Some(rp_id))?;
            if ausschluss.iter().any(|a| vorhanden.iter().any(|v| Some(v.credential_id.as_str()) == a["id"].as_str())) {
                return Err("Für dieses Konto ist hier schon ein Passkey hinterlegt.".into());
            }
        }
        crate::passkey::create_in(&mut vault, request)?
    };
    speichern_im_hintergrund(&app);

    let mut client_data = created.response.client_data_json.clone();
    if !client_hash.is_empty() {
        // Der Browser hat das clientDataJSON selbst gebaut und setzt es
        // ein. Unseres wäre falsch (andere Herkunft), deshalb Platzhalter.
        client_data = B64URL.encode(b"{}");
    }

    let id = created.response.credential_id;
    Ok(json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": client_data,
            "attestationObject": created.response.attestation_object,
            "authenticatorData": B64URL.encode(&created.authenticator_data),
            "publicKey": B64URL.encode(&created.public_key_der),
            "publicKeyAlgorithm": -7,
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    }))
}

fn passkey_anmelden(
    anfrage: &str,
    credential_id: &str,
    herkunft: &str,
    client_hash: &str,
) -> Result<Value, String> {
    let anfrage: Value = serde_json::from_str(anfrage).map_err(|e| format!("Anfrage unlesbar: {e}"))?;
    let rp_id = anfrage["rpId"].as_str().ok_or("Die Anfrage nennt keine Gegenstelle.")?;
    let challenge = anfrage["challenge"].as_str().ok_or("Die Anfrage hat keine Challenge.")?;

    let hash = if client_hash.is_empty() {
        None
    } else {
        let roh = B64URL
            .decode(client_hash.trim_end_matches('='))
            .map_err(|_| "clientDataHash unlesbar.".to_string())?;
        Some(<[u8; 32]>::try_from(roh.as_slice()).map_err(|_| "clientDataHash hat die falsche Länge.".to_string())?)
    };

    let erlaubt: Vec<String> = if credential_id.is_empty() {
        Vec::new()
    } else {
        vec![credential_id.to_string()]
    };

    let app = app()?;
    let state = app.state::<Vault>();
    let antwort = {
        let mut vault = offen(&state)?;
        vault.touch();
        let herkunft = (!herkunft.is_empty()).then_some(herkunft);
        let antwort = crate::passkey::assert_in(&vault, rp_id, challenge, &erlaubt, herkunft, hash)?;
        let _ = crate::entries::mark_accessed(&mut vault, &[antwort.entry_uuid.clone()]);
        antwort
    };

    let _ = app.emit("entries-used", [&antwort.entry_uuid]);

    let client_data = if hash.is_some() { B64URL.encode(b"{}") } else { antwort.client_data_json };
    Ok(json!({
        "id": antwort.credential_id,
        "rawId": antwort.credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": client_data,
            "authenticatorData": antwort.authenticator_data,
            "signature": antwort.signature,
            "userHandle": antwort.user_handle,
        },
        "clientExtensionResults": {},
    }))
}

/* =========================================================
   Werkzeug
   ========================================================= */

fn app() -> Result<tauri::AppHandle, String> {
    crate::app_handle().cloned().ok_or_else(|| "aus".to_string())
}

/// Das Schloss — aber nur, wenn wirklich eine Datenbank offen ist und die
/// Untätigkeitssperre nicht schon gegriffen hätte.
fn offen<'a>(state: &'a Vault) -> Result<std::sync::MutexGuard<'a, VaultState>, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    if vault.database().is_err() || vault.idle_expired() {
        return Err("zu".into());
    }
    Ok(vault)
}

/// Zurückschreiben kostet eine Sekunde Argon2 — der Dienst soll darauf nicht
/// warten. Klappt es nicht, erfährt es die Oberfläche.
fn speichern_im_hintergrund(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        match crate::database::commit(&app, &app.state::<Vault>()) {
            Ok(_) => {
                let _ = app.emit("vault-changed", ());
            }
            Err(err) => {
                eprintln!("[android] Nicht gespeichert: {err}");
                let _ = app.emit("save-failed", err);
            }
        }
    });
}

fn text(env: &mut JNIEnv, wert: &JString) -> String {
    if wert.is_null() {
        return String::new();
    }
    env.get_string(wert).map(Into::into).unwrap_or_default()
}

/// Führt einen Einstieg aus und macht aus allem, was passieren kann, JSON:
/// Ergebnis, Fehler, sogar einen Panic.
fn antworte(
    env: &mut JNIEnv,
    f: impl FnOnce(&mut JNIEnv) -> Result<Value, String>,
) -> jstring {
    let ergebnis = std::panic::catch_unwind(AssertUnwindSafe(|| f(env)))
        .unwrap_or_else(|_| Err("Interner Fehler im Kern.".into()));

    crate::java::abraeumen(env);

    let wert = match ergebnis {
        Ok(wert) => wert,
        // „zu" und „aus" sind Zustände, keine Fehler — die Kotlin-Seite
        // holt dann die App nach vorn.
        Err(e) if e == "zu" || e == "aus" => json!({ "status": e }),
        Err(e) => json!({ "fehler": e }),
    };

    env.new_string(wert.to_string())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
