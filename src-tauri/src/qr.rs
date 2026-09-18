//! QR-Dekodierung auf der Rust-Seite.
//!
//! Der Webview liefert einzelne Kamerabilder (JPEG) oder eine hochgeladene
//! Bilddatei als Bytes; hier wird daraus der Inhalt gelesen. Damit ist der
//! Scanner unabhängig von der BarcodeDetector-API, die es in Firefox und
//! Safari nicht gibt.

use image::GenericImageView;

/// Dekodiert einen QR-Code aus kodierten Bildbytes (PNG, JPEG, WebP …).
///
/// Gibt `Ok(None)` zurück, wenn das Bild gültig war, aber kein Code darin
/// gefunden wurde — das ist beim Kamera-Scan der Normalfall pro Einzelbild
/// und darf kein Fehler sein.
#[tauri::command]
pub fn decode_qr_bytes(bytes: Vec<u8>) -> Result<Option<String>, String> {
    let img = image::load_from_memory(&bytes)
        .map_err(|e| format!("Bild konnte nicht gelesen werden: {e}"))?;
    Ok(decode_dynamic(&img))
}

/// Dekodiert ein Kamerabild in Graustufen — ein Byte je Pixel.
///
/// Zwei Wege, dieselben Daten:
///
/// * **Rohdaten** (Desktop): Die Bytes sind der Anfragekörper, die Breite
///   steht in `x-width`. Kein JPEG, keine Zahlenliste im JSON.
/// * **JSON** (Android): Dort kommt ein roher Körper nicht als solcher an —
///   die Android-Brücke von Tauri reicht nur JSON durch. Dann steht
///   `{ width, data }` darin, `data` als Base64. Früher scheiterte hier
///   jedes Bild still, und der Scanner sah nie einen Code.
#[tauri::command]
pub fn decode_qr_gray(request: tauri::ipc::Request<'_>) -> Result<Option<String>, String> {
    let (width, data): (u32, std::borrow::Cow<'_, [u8]>) = match request.body() {
        tauri::ipc::InvokeBody::Raw(data) => {
            let width = request
                .headers()
                .get("x-width")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .ok_or("Die Bildbreite fehlt.")?;
            (width, data.as_slice().into())
        }
        tauri::ipc::InvokeBody::Json(value) => {
            use base64::Engine;
            let width = value.get("width").and_then(|w| w.as_u64()).ok_or("Die Bildbreite fehlt.")? as u32;
            let text = value.get("data").and_then(|d| d.as_str()).ok_or("Die Bilddaten fehlen.")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| format!("Bilddaten nicht lesbar: {e}"))?;
            (width, bytes.into())
        }
    };
    if width == 0 {
        return Err("Die Bildbreite fehlt.".into());
    }
    let height = data.len() as u32 / width;

    let bild = image::GrayImage::from_raw(width, height, data[..(width * height) as usize].to_vec())
        .ok_or_else(|| "Pixeldaten passen nicht zur angegebenen Größe.".to_string())?;
    Ok(detect(bild))
}

/// Dekodiert aus rohen RGBA-Pixeln, falls der Webview kein JPEG erzeugen kann.
#[tauri::command]
pub fn decode_qr_rgba(width: u32, height: u32, data: Vec<u8>) -> Result<Option<String>, String> {
    let buffer = image::RgbaImage::from_raw(width, height, data)
        .ok_or_else(|| "Pixeldaten passen nicht zur angegebenen Größe.".to_string())?;
    Ok(decode_dynamic(&image::DynamicImage::ImageRgba8(buffer)))
}

/// Liest eine Bilddatei direkt vom Dateisystem.
#[tauri::command]
pub fn decode_qr_path(path: String) -> Result<Option<String>, String> {
    let img = image::open(&path).map_err(|e| format!("Datei konnte nicht gelesen werden: {e}"))?;
    Ok(decode_dynamic(&img))
}

fn decode_dynamic(img: &image::DynamicImage) -> Option<String> {
    // Erster Versuch: Originalgröße in Graustufen.
    if let Some(text) = detect(img.to_luma8()) {
        return Some(text);
    }

    // Zweiter Versuch: verkleinert. Hilft bei sehr großen, leicht unscharfen
    // Kamerabildern, weil das Rauschen mitgemittelt wird.
    let (w, h) = img.dimensions();
    if w.max(h) > 900 {
        let scaled = img.resize(w / 2, h / 2, image::imageops::FilterType::Triangle);
        if let Some(text) = detect(scaled.to_luma8()) {
            return Some(text);
        }
    }

    None
}

fn detect(luma: image::GrayImage) -> Option<String> {
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if !content.is_empty() {
                return Some(content);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ein QR-Code als Graustufenbild: `modul` Pixel je Modul, weißer Rand.
    fn bild(text: &str, modul: u32) -> image::GrayImage {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let breite = code.width() as u32;
        let rand = 4 * modul;
        let kante = breite * modul + 2 * rand;
        let farben = code.to_colors();
        image::GrayImage::from_fn(kante, kante, |x, y| {
            let (x, y) = (x as i64 - rand as i64, y as i64 - rand as i64);
            let innen = x >= 0 && y >= 0 && (x as u32) < breite * modul && (y as u32) < breite * modul;
            let dunkel = innen && farben[(y as u32 / modul * breite + x as u32 / modul) as usize] == qrcode::Color::Dark;
            image::Luma([if dunkel { 0 } else { 255 }])
        })
    }

    const OTP: &str = "otpauth://totp/GitHub:flo%40example.org?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn otpauth_wird_in_allen_groessen_erkannt() {
        for modul in [2, 3, 4, 6] {
            assert_eq!(detect(bild(OTP, modul)).as_deref(), Some(OTP), "Modulgröße {modul}");
        }
    }

    #[test]
    fn link_wird_erkannt() {
        assert_eq!(detect(bild("https://github.com/login", 3)).as_deref(), Some("https://github.com/login"));
    }
}
