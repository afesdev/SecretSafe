use std::{thread, time::Duration};

use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

const CLEAR_AFTER_SECONDS: u64 = 60;

pub fn copy_secret(app: AppHandle, value: String) -> Result<(), String> {
    if value.is_empty() {
        return Err("No hay valor para copiar.".to_string());
    }

    app.clipboard()
        .write_text(value.clone())
        .map_err(|error| error.to_string())?;

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(CLEAR_AFTER_SECONDS));

        if let Ok(current) = app.clipboard().read_text() {
            if current == value {
                let _ = app.clipboard().write_text(String::new());
            }
        }
    });

    Ok(())
}
