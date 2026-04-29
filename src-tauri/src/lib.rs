mod bridge;
mod clipboard;
mod commands;
mod crypto;
mod dialog;
mod error;
mod import;
mod models;
mod password;
mod storage;
mod vault;
mod windows_consent;
mod windows_unlock;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    bridge::start();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::unlock_vault,
            commands::unlock_vault_with_windows,
            commands::enable_windows_unlock,
            commands::disable_windows_unlock,
            commands::is_windows_unlock_enabled,
            commands::list_entries,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::save_vault,
            commands::create_group,
            commands::change_master_password,
            commands::import_keepass_vault,
            commands::import_csv_vault,
            commands::preview_import_source,
            commands::import_external_vault,
            commands::export_vault_csv,
            commands::export_vault_encrypted,
            commands::export_vault_encrypted_with_password,
            commands::list_vault_backups,
            commands::restore_vault_backup,
            commands::get_recovery_settings,
            commands::update_recovery_settings,
            commands::generate_password,
            commands::copy_secret_to_clipboard,
            commands::pick_vault_file,
            commands::choose_vault_save_path,
            commands::pick_import_file,
            commands::choose_export_csv_path,
            commands::choose_export_encrypted_path,
            commands::pick_backup_file,
            commands::get_default_vault_path,
            commands::get_startup_vault_path,
            commands::create_bridge_pair_pin,
            commands::set_bridge_active_session,
            commands::clear_bridge_active_session,
            commands::open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
