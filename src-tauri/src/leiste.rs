//! Das Symbol in der Leiste des Systems (Rechner).
//!
//! Startet der Browser WKeePass, läuft es ohne Fenster (`route::HINTERGRUND`).
//! Damit man trotzdem sieht, dass es läuft — und es ohne Browser öffnen,
//! sperren oder beenden kann —, steht ein Symbol in der Leiste.
//!
//! Unter Linux geht das über StatusNotifierItem (AppIndicator). KDE, Xfce,
//! Cinnamon und Budgie zeigen es von Haus aus; GNOME erst mit der
//! Erweiterung „AppIndicator and KStatusNotifierItem Support“. Fehlt die
//! Bibliothek `libayatana-appindicator3` ganz, bricht das Einrichten mit
//! einem Panic ab — der wird hier aufgefangen, die Anwendung läuft ohne
//! Symbol weiter.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

const OEFFNEN: &str = "oeffnen";
const SPERREN: &str = "sperren";
const BEENDEN: &str = "beenden";

/// Richtet das Symbol ein. Scheitert es, bleibt es bei einer Zeile im
/// Protokoll.
pub fn einrichten(app: &tauri::AppHandle) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bauen(app))) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("Leistensymbol nicht eingerichtet: {err}"),
        Err(_) => eprintln!("Leistensymbol nicht eingerichtet: keine AppIndicator-Bibliothek"),
    }
}

fn bauen(app: &tauri::AppHandle) -> tauri::Result<()> {
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, OEFFNEN, "WKeePass öffnen", true, None::<&str>)?,
            &MenuItem::with_id(app, SPERREN, "Sperren", true, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, BEENDEN, "Beenden", true, None::<&str>)?,
        ],
    )?;

    let mut symbol = TrayIconBuilder::with_id("wkeepass")
        .tooltip("WKeePass")
        .menu(&menu)
        // Links öffnet das Fenster, rechts kommt das Menü — wie gewohnt.
        // (Unter Linux kennt AppIndicator nur das Menü.)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            OEFFNEN => oeffnen(app),
            SPERREN => {
                if let Err(err) = crate::keepass_extension::api::sperren(app, "Über die Leiste gesperrt.") {
                    eprintln!("Sperren über die Leiste: {err}");
                }
            }
            BEENDEN => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|symbol, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                oeffnen(symbol.app_handle());
            }
        });

    if let Some(bild) = app.default_window_icon() {
        symbol = symbol.icon(bild.clone());
    }
    symbol.build(app)?;
    Ok(())
}

/// Holt das Hauptfenster nach vorn — derselbe Weg wie ein zweiter Start.
fn oeffnen(app: &tauri::AppHandle) {
    crate::system::datei_uebergeben(app, std::iter::empty());
}
