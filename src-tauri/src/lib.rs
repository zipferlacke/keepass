//! WKeePass — der Kern.
//!
//! Aufgabenteilung mit der Oberfläche:
//!
//!   Kern     Container ver- und entschlüsseln, Ordner und Einträge führen,
//!            alle Klartextwerte verwahren, TOTP, Hashes, Passwortstärke,
//!            Entsperren (Master-Passwort, PIN, später Biometrie)
//!   Webview  Darstellung und Bedienung — sonst nichts
//!
//! Die Oberfläche bekommt Einträge mit Token statt Werten. Ein Klartextwert
//! geht nur über `vault_reveal_secret` hinaus; beim Kopieren gar nicht, da
//! legt `vault_copy_secret` ihn direkt in die Zwischenablage.
//!
//! Der Vertrag mit der Oberfläche steht in `ui/js/demo.js`: Was dort
//! beantwortet wird, muss hier genauso herauskommen.

mod biometric;
mod database;
mod dto;
mod entries;
mod keepass_extension;
mod keystore;
mod offline;
mod passkey;
mod qr;
mod seal;
mod secrets;
mod settings;
mod state;
mod system;
mod util;
mod webview;

use std::sync::Mutex;

use tauri::{Emitter, Manager};

use state::VaultState;

pub type Vault = Mutex<VaultState>;

/// Wurden wir von einem Browser über Native Messaging gestartet?
///
/// Siehe `main.rs`: Dieselbe Datei bedient beide Rollen, und diese Frage
/// entscheidet, welche.
pub fn started_by_browser() -> bool {
    keepass_extension::route::started_by_browser()
}

/// Arbeitet als Sprachrohr zwischen Browser und laufender Anwendung.
pub fn run_proxy() {
    keepass_extension::route::run_proxy();
}

/// Schreibt jeden Absturz in eine Datei, bevor das Programm endet.
///
/// # Warum das nötig ist
///
/// Unter Linux ruft Tauri **synchrone** Kommandos innerhalb des
/// WebKit-Signalhandlers auf — also aus C heraus. Ein Panic kann dort nicht
/// abgewickelt werden; Rust bricht hart ab und meldet nur
///
/// ```text
/// thread caused non-unwinding panic. aborting.
/// ```
///
/// Der Stapel, der dabei ausgegeben wird, endet bei `main` und verrät die
/// Ursache nicht. Die eigentliche Meldung samt Stelle im Quelltext geht
/// unter, sobald das Fenster weg ist.
///
/// Der Haken läuft **vor** dem Abbruch. Was er aufschreibt, überlebt also
/// den Absturz — Zeitpunkt, Meldung, Datei und Zeile. Mit `RUST_BACKTRACE=1`
/// steht der Stapel gleich mit dabei.
fn install_panic_log() {
    let path = std::env::temp_dir().join("wkeepass-panic.log");
    let previous = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write;

        let where_ = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unbekannte Stelle".into());

        let trace = std::backtrace::Backtrace::force_capture();

        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "\n=== Absturz ===\nStelle: {where_}\n{info}\n\n{trace}");
        }
        eprintln!("Absturzbericht geschrieben nach {}", path.display());

        previous(info);
    }));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_panic_log();

    tauri::Builder::default()
        .manage(Vault::default())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_persisted_scope::init())
        // Nur mobil: Das Plugin deckt ausdrücklich nur Android und iOS ab.
        // Desktop-Biometrie steckt in biometric.rs.
        .plugin({
            #[cfg(any(target_os = "android", target_os = "ios"))]
            { tauri_plugin_biometric::init() }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            { tauri_plugin_persisted_scope::init() }
        })
        .setup(|app| {
            database::start_auto_lock(app.handle().clone());

            // Kanal für die Browser-Erweiterung. Scheitert das Einhängen,
            // läuft die Anwendung trotzdem — nur ohne Browser-Anbindung.
            keepass_extension::api::start(app.handle().clone());

            if let Some(window) = app.get_webview_window("main") {
                // Fensterknöpfe wie auf dem übrigen Schreibtisch.
                webview::apply_decoration_layout(&window);
                // Kamera für das Einlesen von QR-Codes.
                webview::enable_camera(&window);
                // Kein eingebautes Kontextmenü — wir haben ein eigenes.
                webview::suppress_context_menu(&window);

                // Aufs Fenster gezogene Dateien liest der Kern selbst ein und
                // meldet der Oberfläche nur die Verweise — wie beim
                // Auswahldialog. Ob sie gebraucht werden, entscheidet sie:
                // Ohne offenen Eintrag verfallen sie spätestens beim Sperren.
                let handle = app.handle().clone();
                window.on_window_event(move |event| {
                    let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event else {
                        return;
                    };
                    let files: Vec<_> = paths.iter().filter(|p| p.is_file()).cloned().collect();
                    if files.is_empty() {
                        return;
                    }
                    let Some(state) = handle.try_state::<Vault>() else { return };
                    let result = match state.lock() {
                        Ok(mut vault) if vault.db.is_some() => secrets::stage_paths(&mut vault, files),
                        Ok(_) => Err("Zum Ablegen von Dateien muss die Datenbank offen sein.".into()),
                        Err(_) => Err("Kern blockiert.".into()),
                    };
                    let payload = match result {
                        Ok(staged) => serde_json::json!({ "staged": staged }),
                        Err(error) => serde_json::json!({ "error": error }),
                    };
                    let _ = handle.emit("attachments-dropped", payload);
                });
            }
            Ok(())
        })
        // Brücke für tauri-agent-tools — hängt am Feature `agent` und ist in
        // der ausgelieferten Fassung nicht übersetzt.
        .plugin({
            #[cfg(feature = "agent")]
            { tauri_agent_plugin::init() }
            #[cfg(not(feature = "agent"))]
            { tauri_plugin_persisted_scope::init() }
        })
        .invoke_handler(tauri::generate_handler![
            // Entsperren
            database::unlock_methods,
            database::vault_unlock,
            database::vault_create,
            database::app_pin_create,
            database::app_pin_change,
            database::app_pin_clear,
            database::vault_remember,
            database::vault_remember_device,
            database::vault_forget,
            database::confirm_presence,
            // Datenbank
            database::vault_list_entries,
            database::vault_folders,
            database::vault_commit,
            database::vault_lock,
            database::vault_touch,
            database::vault_set_auto_lock,
            // Einträge
            entries::vault_save_entry,
            entries::vault_write_attachment,
            entries::vault_delete_entry,
            entries::vault_empty_recycle_bin,
            entries::vault_move_entry,
            entries::vault_reorder_entry,
            // Ordner
            entries::vault_create_folder,
            entries::vault_rename_folder,
            entries::vault_move_folder,
            entries::vault_remove_folder,
            entries::vault_reorder_folder,
            // Geheimnisse
            secrets::vault_new_secret,
            secrets::vault_set_secret,
            secrets::vault_drop_secret,
            secrets::vault_reveal_secret,
            secrets::vault_copy_secret,
            // Auswertungen
            secrets::vault_strength,
            secrets::vault_hash_prefix,
            secrets::vault_duplicate_groups,
            secrets::vault_totp,
            // Anhänge
            secrets::vault_attachment,
            secrets::pick_attachments,
            secrets::save_attachment,
            secrets::stage_attachment_content,
            // Einstellungen
            settings::settings_read,
            settings::settings_write,
            // System
            system::startup_database,
            system::pick_database_file,
            system::pick_save_path,
            system::fetch_page_title,
            // Passkeys
            passkey::passkey_list,
            passkey::passkey_create,
            passkey::passkey_assert,
            passkey::passkey_delete,
            // Browser-Erweiterung
            keepass_extension::api::browser_answer,
            keepass_extension::api::browser_pending,
            keepass_extension::api::browser_identified,
            keepass_extension::api::browser_status,
            keepass_extension::api::browser_install,
            keepass_extension::api::browser_uninstall,
            keepass_extension::api::browser_forget,
            // QR
            qr::decode_qr_bytes,
            qr::decode_qr_rgba,
            qr::decode_qr_path,
        ])
        .run(tauri::generate_context!())
        .expect("Anwendung konnte nicht gestartet werden");
}
