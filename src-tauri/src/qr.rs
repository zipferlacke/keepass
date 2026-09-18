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

/// Dekodiert ein Kamerabild in Graustufen, als rohe Bytes ohne JSON.
///
/// Der schnelle Weg für den Kamera-Scan: Der Webview schickt ein Byte je
/// Pixel direkt als Anfragekörper, die Breite steht in `x-width`. Kein
/// JPEG, das erst entpackt werden müsste, keine Zahlenliste im JSON — das
/// machte die Erkennung vorher träge.
#[tauri::command]
pub fn decode_qr_gray(request: tauri::ipc::Request<'_>) -> Result<Option<String>, String> {
    let tauri::ipc::InvokeBody::Raw(data) = request.body() else {
        return Err("Erwartet werden rohe Bilddaten.".into());
    };
    let width: u32 = request
        .headers()
        .get("x-width")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .filter(|w| *w > 0)
        .ok_or("Die Bildbreite fehlt.")?;
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
