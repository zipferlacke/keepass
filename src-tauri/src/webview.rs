//! Feinheiten am Webview, die sich nicht über die Konfiguration einstellen
//! lassen.
//!
//! # Das Kontextmenü
//!
//! Der Webview zeigt beim Rechtsklick sein eigenes Menü (unter WebKitGTK mit
//! „Element untersuchen", „Neu laden" u. a.). Die Anwendung hat ein eigenes
//! Kontextmenü, daher wird das des Webviews abgeschaltet.
//!
//!   * „Element untersuchen" erscheint nur bei eingeschalteten
//!     Entwicklerwerkzeugen, also in Entwicklungsfassungen.
//!   * Das restliche Menü (Kopieren, Neu laden) bleibt auch in gebauten Fassungen
//!     und wird in Rust beim Webview abgeschaltet, nicht per `contextmenu`-Zuhörer
//!     in JavaScript.

/// Setzt die Reihenfolge der Fensterknöpfe auf die des Schreibtischs.
///
/// # Hintergrund
///
/// Unter Wayland zeichnet GNOME keine Fensterleisten, die Anwendung malt sie selbst.
/// Die Knöpfe stehen sonst in der GTK-Einstellung `gtk-decoration-layout`. `tao`,
/// die Fensterschicht unter Tauri, hängt dem Fenster aber eine eigene `GtkHeaderBar`
/// an und setzt die Reihenfolge fest:
///
/// ```text
/// // tao/src/platform_impl/linux/wayland/header.rs
/// HeaderBar::builder().decoration_layout("menu:minimize,maximize,close")
/// ```
///
/// Die Eigenschaft am Widget hat Vorrang vor der globalen Einstellung. Die Funktion
/// sucht diese Kopfleiste und überschreibt ihre Reihenfolge mit dem Wert, den GTK
/// für den Schreibtisch vorsieht. `"maximizable": false` in der Konfiguration
/// entfiele, da es das Maximieren und den Doppelklick auf die Leiste ganz
/// abschaltet; so verschwindet nur der Knopf.
pub fn apply_decoration_layout(window: &tauri::WebviewWindow) {
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
    {
        use gtk::prelude::HeaderBarExt;

        let Some(layout) = desktop_button_layout() else {
            return;
        };
        let Ok(gtk_window) = window.gtk_window() else {
            return;
        };
        let Some(titlebar) = gtk::prelude::GtkWindowExt::titlebar(&gtk_window) else {
            return;
        };
        let Some(header) = find_header_bar(&titlebar) else {
            return;
        };
        header.set_decoration_layout(Some(&layout));
    }

    #[cfg(not(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android")))))]
    {
        // macOS und Windows zeichnen ihre Fensterleisten selbst und halten
        // sich dabei an die Vorgaben des Systems.
        let _ = window;
    }
}

/// Was GTK für diesen Schreibtisch als Knopfreihenfolge vorsieht.
///
/// Diese Einstellung ist bereits übersetzt: GNOME schreibt `appmenu:…` in seine
/// Einstellungen, GTK macht daraus `menu:…`; unter KDE füllt `kde-gtk-config`
/// denselben Wert. Es genügt, GTK zu fragen.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
fn desktop_button_layout() -> Option<String> {
    use gtk::glib::object::ObjectExt;

    let settings = gtk::Settings::default()?;
    let layout: String = settings.property("gtk-decoration-layout");
    (!layout.is_empty()).then_some(layout)
}

/// Sucht die Kopfleiste im Fensteraufbau.
///
/// `tao` verpackt sie in eine `EventBox`, damit sich das Fenster daran ziehen
/// lässt; deshalb wird der Aufbau rekursiv durchsucht.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
fn find_header_bar(widget: &gtk::Widget) -> Option<gtk::HeaderBar> {
    use gtk::prelude::{ContainerExt, Cast};

    if let Ok(header) = widget.clone().downcast::<gtk::HeaderBar>() {
        return Some(header);
    }

    let container = widget.clone().downcast::<gtk::Container>().ok()?;
    container.children().iter().find_map(find_header_bar)
}

/// Gibt die Kamera frei — für das Einlesen von QR-Codes.
///
/// Zwei Voraussetzungen, die `wry` nicht erfüllt:
///
///  1. `enable-media-stream` ist in WebKitGTK standardmäßig aus; `getUserMedia`
///     scheitert sonst mit „not allowed by the user agent or the platform in the
///     current context".
///  2. Jede Anfrage muss einzeln beantwortet werden; ohne Zuhörer am Signal
///     `permission-request` gilt sie als abgelehnt.
///
/// Erlaubt wird ausschließlich die Kamera. Standort, Benachrichtigungen, Mikrofon
/// und Bildschirmaufnahme werden abgelehnt.
pub fn enable_camera(window: &tauri::WebviewWindow) {
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
    {
        use webkit2gtk::gio::prelude::Cast;
        use webkit2gtk::{
            PermissionRequestExt, SettingsExt, UserMediaPermissionRequest,
            UserMediaPermissionRequestExt, WebViewExt,
        };

        let _ = window.with_webview(|webview| {
            let view = webview.inner();

            if let Some(settings) = WebViewExt::settings(&view) {
                settings.set_enable_media_stream(true);
            }

            view.connect_permission_request(|_, request| {
                // Der Rückruf läuft aus C heraus; ein Panic könnte dort nicht abgewickelt
                // werden und würde das Programm abbrechen. Er wird daher abgefangen, im Zweifel
                // gilt die Anfrage als abgelehnt.
                let answered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let camera = request
                        .downcast_ref::<UserMediaPermissionRequest>()
                        .is_some_and(|media| media.is_for_video_device());

                    if camera {
                        request.allow();
                    } else {
                        request.deny();
                    }
                }));

                if answered.is_err() {
                    eprintln!("Berechtigungsanfrage konnte nicht beantwortet werden.");
                }

                // `true` heißt: beantwortet, nicht weiterreichen.
                true
            });
        });
    }

    #[cfg(not(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android")))))]
    {
        // macOS und Windows fragen den Nutzer selbst; auf Android regelt es
        // die Berechtigung im Manifest.
        let _ = window;
    }
}

/// Schaltet das eingebaute Kontextmenü des Webviews ab — **nur in der
/// ausgelieferten Fassung**.
///
/// In der Entwicklung bleibt es an, da es „Element untersuchen" enthält; die
/// Entwicklerwerkzeuge sind sonst nur über Strg+Umschalt+I erreichbar. In der
/// fertigen Fassung ersetzt das eigene Kontextmenü es.
pub fn suppress_context_menu(window: &tauri::WebviewWindow) {
    if cfg!(debug_assertions) {
        return;
    }

    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
    {
        use webkit2gtk::WebViewExt;

        let _ = window.with_webview(|webview| {
            // `true` heißt: Das Ereignis ist behandelt, kein Menü zeigen.
            webview.inner().connect_context_menu(|_, _, _, _| true);
        });
    }

    #[cfg(not(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android")))))]
    {
        // macOS  WKWebView: `allowsLinkPreview = false` plus ein eigener
        //        `menu(for:)`-Handler auf der Unterklasse
        // Windows WebView2: `CoreWebView2Settings.AreDefaultContextMenusEnabled = false`
        let _ = window;
    }
}
