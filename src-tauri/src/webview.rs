//! Feinheiten am Webview, die sich nicht über die Konfiguration einstellen
//! lassen.
//!
//! # Das Kontextmenü
//!
//! Beim Rechtsklick zeigt der Webview sein eigenes Menü — unter WebKitGTK
//! mit „Element untersuchen", „Neu laden" und Ähnlichem. Für einen
//! Passwortmanager ist das nichts, was der Nutzer sehen soll: Wir haben ein
//! eigenes Kontextmenü, und der Eintrag zum Untersuchen führt in die
//! Entwicklerwerkzeuge.
//!
//! Zwei Dinge sind zu unterscheiden:
//!
//!   * **„Element untersuchen"** taucht nur auf, wenn die
//!     Entwicklerwerkzeuge eingeschaltet sind. Das ist in
//!     Entwicklungsfassungen der Fall und verschwindet in einer mit
//!     `cargo tauri build` gebauten Fassung von selbst.
//!   * **Das restliche Menü** (Kopieren, Neu laden) bleibt auch dort. Wer es
//!     ganz loswerden will, muss den Webview selbst fragen.
//!
//! Genau das passiert hier — in Rust, nicht mit einem `contextmenu`-Zuhörer
//! in JavaScript. Ein Zuhörer ließe sich umgehen und müsste in jeder Ansicht
//! mitgedacht werden; hier fällt die Entscheidung eine Ebene tiefer.

/// Setzt die Reihenfolge der Fensterknöpfe auf die des Schreibtischs.
///
/// # Warum das nötig ist
///
/// Unter Wayland zeichnet GNOME keine Fensterleisten — die Anwendung malt
/// sie selbst. Welche Knöpfe erscheinen, steht normalerweise in der
/// GTK-Einstellung `gtk-decoration-layout`; auf diesem Schreibtisch etwa
/// `menu:minimize,close`, also ohne Maximieren.
///
/// `tao`, die Fensterschicht unter Tauri, hängt dem Fenster jedoch eine
/// eigene `GtkHeaderBar` an und schreibt die Reihenfolge fest hinein:
///
/// ```text
/// // tao/src/platform_impl/linux/wayland/header.rs
/// HeaderBar::builder().decoration_layout("menu:minimize,maximize,close")
/// ```
///
/// Am Widget gesetzt schlägt diese Eigenschaft die globale Einstellung.
/// Deshalb hatte unser Fenster als einziges einen Maximieren-Knopf, und
/// deshalb hilft es nichts, an `gtk-decoration-layout` zu drehen.
///
/// # Was hier passiert
///
/// Wir suchen genau diese Kopfleiste und überschreiben ihre Reihenfolge mit
/// dem, was GTK für diesen Schreibtisch vorsieht. Bewusst nicht über
/// `"maximizable": false` in der Konfiguration: Das nähme dem Fenster die
/// Fähigkeit zu maximieren und damit auch den Doppelklick auf die Leiste.
/// Hier verschwindet nur der Knopf.
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
/// Diese Einstellung ist bereits übersetzt — GNOME schreibt `appmenu:…` in
/// seine eigenen Einstellungen, GTK bekommt daraus `menu:…`. Unter KDE füllt
/// `kde-gtk-config` denselben Wert. Wir müssen also nichts über den
/// Schreibtisch wissen, nur GTK fragen.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios", target_os = "android"))))]
fn desktop_button_layout() -> Option<String> {
    use gtk::glib::object::ObjectExt;

    let settings = gtk::Settings::default()?;
    let layout: String = settings.property("gtk-decoration-layout");
    (!layout.is_empty()).then_some(layout)
}

/// Sucht die Kopfleiste im Fensteraufbau.
///
/// `tao` verpackt sie in eine `EventBox`, damit sich das Fenster daran
/// ziehen lässt — wir dürfen also nicht nur die oberste Ebene ansehen.
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
/// WebKitGTK liefert zwei Hürden, und `wry` nimmt keine davon:
///
///  1. `enable-media-stream` ist **aus**. Solange das so ist, scheitert
///     `getUserMedia` mit „not allowed by the user agent or the platform in
///     the current context" — es fragt gar nicht erst.
///  2. Auch eingeschaltet muss jede Anfrage einzeln beantwortet werden. Ohne
///     Zuhörer am Signal `permission-request` gilt sie als abgelehnt.
///
/// Wir erlauben ausschließlich die Kamera. Alles andere — Standort,
/// Benachrichtigungen, Mikrofon, Bildschirmaufnahme — wird abgelehnt, statt
/// pauschal durchzuwinken: Ein Passwortmanager hat davon nichts, und was
/// nicht gebraucht wird, bleibt zu.
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
                // Der Rückruf läuft aus C heraus. Ein Panic könnte hier nicht
                // abgewickelt werden und würde das Programm hart abbrechen —
                // „thread caused non-unwinding panic. aborting." Deshalb wird
                // er hier abgefangen: Im Zweifel gilt die Anfrage als
                // abgelehnt, und die App läuft weiter.
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
/// Beim Entwickeln bleibt es an: Darin steckt „Element untersuchen", und
/// ohne das kommt man an die Entwicklerwerkzeuge nur noch über
/// Strg+Umschalt+I. Für einen Passwortmanager gehört das Menü in der
/// fertigen Fassung trotzdem weg — wir haben ein eigenes, und der Eintrag
/// zum Untersuchen hat dort nichts zu suchen.
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
