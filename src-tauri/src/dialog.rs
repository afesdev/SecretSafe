use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

pub fn pick_vault_file(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("SecretSafe vault", &["vault"])
        .blocking_pick_file();

    path.map(file_path_to_string).transpose()
}

pub fn choose_vault_save_path(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("SecretSafe vault", &["vault"])
        .set_file_name("secretsafe.vault")
        .blocking_save_file();

    path.map(file_path_to_string).transpose()
}

pub fn pick_import_file(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("KeePass database", &["kdbx", "kdb"])
        .add_filter("1Password exchange", &["1pif", "1pux"])
        .add_filter("Bitwarden CSV", &["csv"])
        .add_filter("1Password CSV", &["csv"])
        .add_filter("CSV", &["csv"])
        .blocking_pick_file();

    path.map(file_path_to_string).transpose()
}

pub fn choose_export_csv_path(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("CSV", &["csv"])
        .set_file_name("secretsafe-export.csv")
        .blocking_save_file();

    path.map(file_path_to_string).transpose()
}

pub fn choose_export_encrypted_path(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("SecretSafe encrypted vault", &["vault"])
        .set_file_name("secretsafe-export.vault")
        .blocking_save_file();

    path.map(file_path_to_string).transpose()
}

pub fn pick_backup_file(app: AppHandle) -> Result<Option<String>, String> {
    let path = app
        .dialog()
        .file()
        .add_filter("Backup SecretSafe", &["vault"])
        .blocking_pick_file();

    path.map(file_path_to_string).transpose()
}

fn file_path_to_string(path: tauri_plugin_dialog::FilePath) -> Result<String, String> {
    path.into_path()
        .map(|path| path.to_string_lossy().to_string())
        .map_err(|error| error.to_string())
}
