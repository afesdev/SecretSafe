use crate::{
    bridge, clipboard, dialog,
    models::{
        BackupItem, BridgePairPin, GeneratedPassword, ImportPreview, ImportResult,
        PasswordGenerationOptions, RecoverySettings, SecretEntry, SecretEntryInput,
        SecretEntryUpdateInput, VaultData, VaultSummary, WindowsUnlockResult,
    },
    password,
    storage::{default_vault_path, normalize_vault_path},
    vault, windows_consent, windows_unlock,
};
use std::path::Path;
use tauri_plugin_opener::OpenerExt;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImportOptions {
    pub selected_indices: Option<Vec<usize>>,
}

#[tauri::command]
pub fn create_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
) -> Result<VaultSummary, String> {
    vault::create_vault(normalize_vault_path(&app, vault_path)?, &master_password)
        .map_err(to_command_error)
}

#[tauri::command]
pub fn unlock_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
) -> Result<VaultData, String> {
    vault::unlock_vault(normalize_vault_path(&app, vault_path)?, &master_password)
        .map_err(to_command_error)
}

#[tauri::command]
pub async fn unlock_vault_with_windows(
    app: tauri::AppHandle,
    vault_path: String,
) -> Result<WindowsUnlockResult, String> {
    windows_consent::verify_windows_user()
        .await
        .map_err(to_command_error)?;
    let vault_path = normalize_vault_path(&app, vault_path)?;
    windows_unlock::unlock_vault_with_windows(&app, vault_path).map_err(to_command_error)
}

#[tauri::command]
pub fn enable_windows_unlock(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
) -> Result<(), String> {
    let vault_path = normalize_vault_path(&app, vault_path)?;
    windows_unlock::enable_windows_unlock(&app, vault_path, &master_password).map_err(to_command_error)
}

#[tauri::command]
pub fn disable_windows_unlock(app: tauri::AppHandle, vault_path: String) -> Result<(), String> {
    let vault_path = normalize_vault_path(&app, vault_path)?;
    windows_unlock::disable_windows_unlock(&app, vault_path).map_err(to_command_error)
}

#[tauri::command]
pub fn is_windows_unlock_enabled(
    app: tauri::AppHandle,
    vault_path: String,
) -> Result<bool, String> {
    let vault_path = normalize_vault_path(&app, vault_path)?;
    windows_unlock::is_windows_unlock_enabled(&app, vault_path).map_err(to_command_error)
}

#[tauri::command]
pub fn list_entries(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
) -> Result<Vec<SecretEntry>, String> {
    vault::unlock_vault(normalize_vault_path(&app, vault_path)?, &master_password)
        .map(|vault| vault.entries)
        .map_err(to_command_error)
}

#[tauri::command]
pub fn add_entry(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    entry: SecretEntryInput,
) -> Result<VaultData, String> {
    vault::add_entry(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        entry,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn update_entry(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    entry: SecretEntryUpdateInput,
) -> Result<VaultData, String> {
    vault::update_entry(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        entry,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn delete_entry(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    entry_id: uuid::Uuid,
) -> Result<VaultData, String> {
    vault::delete_entry(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        entry_id,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn save_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    vault_data: VaultData,
) -> Result<VaultSummary, String> {
    vault::save_vault(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        vault_data,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn create_group(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    group: String,
) -> Result<VaultData, String> {
    vault::create_group(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        group,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn change_master_password(
    app: tauri::AppHandle,
    vault_path: String,
    current_master_password: String,
    new_master_password: String,
) -> Result<VaultSummary, String> {
    vault::change_master_password(
        normalize_vault_path(&app, vault_path)?,
        &current_master_password,
        &new_master_password,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn import_keepass_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    keepass_path: String,
    keepass_password: String,
) -> Result<ImportResult, String> {
    let (vault, summary) = vault::import_keepass_vault(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        keepass_path,
        &keepass_password,
    )
    .map_err(to_command_error)?;

    Ok(ImportResult { vault, summary })
}

#[tauri::command]
pub fn import_csv_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    csv_path: String,
) -> Result<ImportResult, String> {
    let (vault, summary) = vault::import_csv_vault(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        csv_path,
    )
    .map_err(to_command_error)?;

    Ok(ImportResult { vault, summary })
}

#[tauri::command]
pub fn preview_import_source(source_path: String) -> Result<ImportPreview, String> {
    vault::preview_import_source(source_path).map_err(to_command_error)
}

#[tauri::command]
pub fn import_external_vault(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    source_path: String,
    source_password: String,
    options: Option<ExternalImportOptions>,
) -> Result<ImportResult, String> {
    let (vault, summary) = vault::import_external_vault(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        source_path,
        &source_password,
        options.and_then(|value| value.selected_indices),
    )
    .map_err(to_command_error)?;
    Ok(ImportResult { vault, summary })
}

#[tauri::command]
pub fn export_vault_csv(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    csv_path: String,
) -> Result<usize, String> {
    vault::export_vault_csv(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        csv_path,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn export_vault_encrypted(
    app: tauri::AppHandle,
    vault_path: String,
    export_path: String,
) -> Result<(), String> {
    vault::export_vault_encrypted(normalize_vault_path(&app, vault_path)?, export_path)
        .map_err(to_command_error)
}

#[tauri::command]
pub fn export_vault_encrypted_with_password(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    export_password: String,
    export_path: String,
) -> Result<(), String> {
    vault::export_vault_encrypted_with_password(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        &export_password,
        export_path,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn list_vault_backups(
    app: tauri::AppHandle,
    vault_path: String,
) -> Result<Vec<BackupItem>, String> {
    vault::list_vault_backups(normalize_vault_path(&app, vault_path)?).map_err(to_command_error)
}

#[tauri::command]
pub fn restore_vault_backup(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    backup_path: String,
) -> Result<VaultData, String> {
    vault::restore_vault_from_backup(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        backup_path,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn get_recovery_settings(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
) -> Result<RecoverySettings, String> {
    vault::get_recovery_settings(normalize_vault_path(&app, vault_path)?, &master_password)
        .map_err(to_command_error)
}

#[tauri::command]
pub fn update_recovery_settings(
    app: tauri::AppHandle,
    vault_path: String,
    master_password: String,
    recovery: RecoverySettings,
) -> Result<RecoverySettings, String> {
    vault::update_recovery_settings(
        normalize_vault_path(&app, vault_path)?,
        &master_password,
        recovery,
    )
    .map_err(to_command_error)
}

#[tauri::command]
pub fn generate_password(
    options: Option<PasswordGenerationOptions>,
) -> Result<GeneratedPassword, String> {
    password::generate_password(options).map_err(to_command_error)
}

#[tauri::command]
pub fn copy_secret_to_clipboard(app: tauri::AppHandle, value: String) -> Result<(), String> {
    clipboard::copy_secret(app, value)
}

#[tauri::command]
pub fn pick_vault_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::pick_vault_file(app)
}

#[tauri::command]
pub fn choose_vault_save_path(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::choose_vault_save_path(app)
}

#[tauri::command]
pub fn pick_import_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::pick_import_file(app)
}

#[tauri::command]
pub fn choose_export_csv_path(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::choose_export_csv_path(app)
}

#[tauri::command]
pub fn choose_export_encrypted_path(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::choose_export_encrypted_path(app)
}

#[tauri::command]
pub fn pick_backup_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    dialog::pick_backup_file(app)
}

#[tauri::command]
pub fn get_default_vault_path(app: tauri::AppHandle) -> Result<String, String> {
    default_vault_path(&app).map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn get_startup_vault_path() -> Option<String> {
    std::env::args().skip(1).find(|arg| is_vault_file(arg))
}

#[tauri::command]
pub fn create_bridge_pair_pin() -> BridgePairPin {
    bridge::create_pair_pin()
}

#[tauri::command]
pub fn set_bridge_active_session(vault_path: String, master_password: String) {
    bridge::set_active_session(vault_path, master_password);
}

#[tauri::command]
pub fn clear_bridge_active_session() {
    bridge::clear_active_session();
}

#[tauri::command]
pub fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let url = normalize_url(&url)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(to_command_error)
}

fn normalize_url(url: &str) -> Result<String, String> {
    let url = url.trim();

    if url.is_empty() {
        return Err("La URL está vacía".to_string());
    }

    if url.starts_with("https://") || url.starts_with("http://") {
        return Ok(url.to_string());
    }

    if url.contains("://") {
        return Err("Solo se permiten enlaces http o https".to_string());
    }

    Ok(format!("https://{url}"))
}

fn is_vault_file(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("vault"))
}

fn to_command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
