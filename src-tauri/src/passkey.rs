//! Passkeys — WebAuthn-Schlüsselpaare in der Datenbank.
//!
//! # Woher die Anfrage kommt
//!
//! Ein Passkey entsteht **nie** in dieser Oberfläche. Den Anstoß gibt immer
//! die Gegenstelle:
//!
//! ```text
//! Desktop  Browser-Erweiterung → Native-Messaging-Host → hier
//! Android  CredentialProviderService → hier
//! ```
//!
//! Die Oberfläche zeigt anschließend nur an, was vorhanden ist. Deshalb sind
//! die Kommandos hier plattformunabhängig: Sie machen die Krypto und die
//! Ablage, der Transport ist ein eigenes Programm.
//!
//! # Ablage
//!
//! In denselben Feldern wie KeePassXC, damit beide Programme dieselben
//! Passkeys sehen. Der private Schlüssel liegt als PEM in einem geschützten
//! Feld — genau wie ein Passwort, also im Kern und nie im Webview.
//!
//! ```text
//! KPEX_PASSKEY_RELYING_PARTY     github.com
//! KPEX_PASSKEY_USERNAME          anzeigename
//! KPEX_PASSKEY_CREDENTIAL_ID     base64url
//! KPEX_PASSKEY_USER_HANDLE       base64url
//! KPEX_PASSKEY_PRIVATE_KEY_PEM   -----BEGIN PRIVATE KEY----- …
//! ```
//!
//! # Was hier bewusst fehlt
//!
//! Der Signaturzähler. WebAuthn erlaubt ihn wegzulassen (Wert 0), und bei
//! einer Datei, die auf mehreren Geräten liegt, würde er ohnehin
//! auseinanderlaufen und Anmeldungen abweisen. KeePassXC macht es genauso.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::ensure_group;
use crate::Vault;

/// Ordner, in dem Passkeys liegen.
pub const FOLDER: &str = "Passkeys";

const F_RP: &str = "KPEX_PASSKEY_RELYING_PARTY";
const F_USER: &str = "KPEX_PASSKEY_USERNAME";
/// Woran ein Passkey-Eintrag zu erkennen ist — auch von außerhalb dieses
/// Moduls. Die Browser-Anbindung hält solche Einträge aus der Passwortliste
/// heraus (siehe `keepass_extension::api::matching_entries`).
pub const F_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
const F_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
const F_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    /// Domain der Gegenstelle, etwa `github.com`.
    pub rp_id: String,
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: Option<String>,
    /// Base64url, kommt von der Website.
    pub challenge: String,
    #[serde(default)]
    pub user_handle: Option<String>,
    /// `https://github.com` — geht so in das clientDataJSON.
    #[serde(default)]
    pub origin: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub entry_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    pub credential_id: String,
    /// Base64url, CBOR — enthält die authenticatorData samt öffentlichem Schlüssel.
    pub attestation_object: String,
    pub client_data_json: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertResponse {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
    /// Welcher Eintrag angemeldet hat — nur für „Zuletzt genutzt", geht
    /// nicht an die Gegenstelle.
    #[serde(skip)]
    pub entry_uuid: String,
}

/* =========================================================
   Auflisten und Entfernen
   ========================================================= */

#[tauri::command]
pub fn passkey_list(state: tauri::State<'_, Vault>) -> Result<Vec<PasskeyInfo>, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database()?;

    Ok(db
        .iter_all_entries()
        .filter_map(|e| {
            Some(PasskeyInfo {
                credential_id: e.get(F_ID)?.to_string(),
                rp_id: e.get(F_RP).unwrap_or_default().to_string(),
                user_name: e.get(F_USER).unwrap_or_default().to_string(),
                entry_id: e.id().uuid().to_string(),
            })
        })
        .collect())
}

#[tauri::command]
pub fn passkey_delete(
    state: tauri::State<'_, Vault>,
    #[allow(non_snake_case)] credentialId: String,
) -> Result<bool, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database_mut()?;

    let Some(id) = db
        .iter_all_entries()
        .find(|e| e.get(F_ID) == Some(credentialId.as_str()))
        .map(|e| e.id())
    else {
        return Ok(false);
    };

    db.entry_mut(id).ok_or("Eintrag verschwunden.")?.track_changes().remove();
    Ok(true)
}

/* =========================================================
   Anlegen
   ========================================================= */

#[tauri::command]
pub fn passkey_create(
    state: tauri::State<'_, Vault>,
    request: CreateRequest,
) -> Result<CreateResponse, String> {
    let mut vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;

    // ES256, also P-256 mit SHA-256 — das, was jede Gegenstelle versteht.
    let signing = SigningKey::random(&mut rand_core::OsRng);
    let pem = signing
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("Schlüssel nicht ablegbar: {e}"))?
        .to_string();

    let mut raw_id = [0u8; 32];
    getrandom_bytes(&mut raw_id);
    let credential_id = B64URL.encode(raw_id);

    let user_handle = request
        .user_handle
        .clone()
        .unwrap_or_else(|| B64URL.encode(request.user_name.as_bytes()));

    let client_data = client_data("webauthn.create", &request.challenge, request.origin.as_deref(), &request.rp_id);
    let auth_data = authenticator_data(&request.rp_id, Some((&raw_id, signing.verifying_key())));

    let attestation = attestation_object(&auth_data);

    // Eintrag anlegen — der private Schlüssel als geschütztes Feld.
    let title = format!("{} ({})", request.rp_id, request.user_name);
    {
        let db = vault.database_mut()?;
        let group = ensure_group(db, FOLDER);

        let id = {
            let mut g = db.group_mut(group).ok_or("Passkey-Ordner fehlt.")?;
            g.add_entry().id()
        };

        let mut entry = db.entry_mut(id).ok_or("Eintrag verschwunden.")?;
        entry.set_unprotected(keepass::db::fields::TITLE, title);
        entry.set_unprotected(keepass::db::fields::USERNAME, request.user_name.clone());
        entry.set_unprotected(keepass::db::fields::URL, format!("https://{}", request.rp_id));
        entry.set_unprotected(F_RP, request.rp_id.clone());
        entry.set_unprotected(F_USER, request.user_display_name.clone().unwrap_or(request.user_name));
        entry.set_unprotected(F_ID, credential_id.clone());
        entry.set_unprotected(F_HANDLE, user_handle);
        entry.set_protected(F_KEY, pem);
        entry.times.last_modification = Some(keepass::db::Times::now());
    }

    Ok(CreateResponse {
        credential_id,
        attestation_object: B64URL.encode(attestation),
        client_data_json: B64URL.encode(client_data),
    })
}

/* =========================================================
   Anmelden
   ========================================================= */

#[tauri::command]
pub fn passkey_assert(
    state: tauri::State<'_, Vault>,
    #[allow(non_snake_case)] rpId: String,
    challenge: String,
    #[allow(non_snake_case)] credentialId: Option<String>,
    origin: Option<String>,
) -> Result<AssertResponse, String> {
    let vault = state.lock().map_err(|_| "Kern blockiert.".to_string())?;
    let db = vault.database()?;

    let entry = db
        .iter_all_entries()
        .find(|e| {
            e.get(F_RP) == Some(rpId.as_str())
                && credentialId.as_deref().is_none_or(|id| e.get(F_ID) == Some(id))
        })
        .ok_or("Für diese Gegenstelle ist kein Passkey hinterlegt.")?;

    let pem = entry.get(F_KEY).ok_or("Der Passkey hat keinen Schlüssel.")?;
    let signing = SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| format!("Schlüssel nicht lesbar: {e}"))?;

    let client_data = client_data("webauthn.get", &challenge, origin.as_deref(), &rpId);
    let auth_data = authenticator_data(&rpId, None);

    // Signiert wird über authenticatorData ‖ SHA-256(clientDataJSON).
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));

    let signature: Signature = signing.sign(&message);

    Ok(AssertResponse {
        credential_id: entry.get(F_ID).unwrap_or_default().to_string(),
        authenticator_data: B64URL.encode(&auth_data),
        client_data_json: B64URL.encode(&client_data),
        signature: B64URL.encode(signature.to_der().as_bytes()),
        user_handle: entry.get(F_HANDLE).map(str::to_string),
        entry_uuid: entry.id().uuid().to_string(),
    })
}

/* =========================================================
   WebAuthn-Bausteine
   ========================================================= */

fn client_data(kind: &str, challenge: &str, origin: Option<&str>, rp_id: &str) -> Vec<u8> {
    let origin = origin.map(str::to_string).unwrap_or_else(|| format!("https://{rp_id}"));
    format!(
        r#"{{"type":"{kind}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// `authenticatorData` nach WebAuthn.
///
/// Bei `Some(..)` wird die attestedCredentialData angehängt — das ist der
/// Fall beim Anlegen. Beim Anmelden bleibt es bei Hash, Flags und Zähler.
fn authenticator_data(
    rp_id: &str,
    credential: Option<(&[u8; 32], &p256::ecdsa::VerifyingKey)>,
) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();

    // UP (Nutzer anwesend) | UV (Nutzer geprüft) | AT, falls Daten folgen
    let mut flags = 0x01 | 0x04;
    if credential.is_some() {
        flags |= 0x40;
    }
    data.push(flags);
    data.extend_from_slice(&0u32.to_be_bytes()); // Zähler, siehe Modulkommentar

    if let Some((id, key)) = credential {
        data.extend_from_slice(&[0u8; 16]); // AAGUID: keiner, wir sind kein Gerät
        data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(&cose_key(key));
    }
    data
}

/// Öffentlicher Schlüssel als COSE_Key (CBOR), wie WebAuthn ihn erwartet.
fn cose_key(key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    let x = point.x().expect("P-256 hat eine x-Koordinate");
    let y = point.y().expect("P-256 hat eine y-Koordinate");

    // Reihenfolge nach der COSE-Norm: 1, 3, -1, -2, -3. Deshalb eine Liste
    // und keine Abbildung — die würde umsortieren.
    let value = ciborium::Value::Map(vec![
        (ciborium::Value::Integer(1.into()), ciborium::Value::Integer(2.into())),      // kty: EC2
        (ciborium::Value::Integer(3.into()), ciborium::Value::Integer((-7).into())),   // alg: ES256
        (ciborium::Value::Integer((-1).into()), ciborium::Value::Integer(1.into())),   // crv: P-256
        (ciborium::Value::Integer((-2).into()), ciborium::Value::Bytes(x.to_vec())),
        (ciborium::Value::Integer((-3).into()), ciborium::Value::Bytes(y.to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR schreibt in einen Vec immer");
    out
}

/// `attestationObject` in der Form „none" — ohne Herstellernachweis.
///
/// Das ist für Passwortmanager der übliche Weg: Wir sind kein zertifiziertes
/// Gerät und behaupten es auch nicht.
fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let value = ciborium::Value::Map(vec![
        (ciborium::Value::Text("fmt".into()), ciborium::Value::Text("none".into())),
        (ciborium::Value::Text("attStmt".into()), ciborium::Value::Map(vec![])),
        (ciborium::Value::Text("authData".into()), ciborium::Value::Bytes(auth_data.to_vec())),
    ]);

    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR schreibt in einen Vec immer");
    out
}

fn getrandom_bytes(buffer: &mut [u8]) {
    use chacha20poly1305::aead::rand_core::RngCore;
    chacha20poly1305::aead::OsRng.fill_bytes(buffer);
}
