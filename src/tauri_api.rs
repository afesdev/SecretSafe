#![allow(dead_code)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

pub type ApiResult<T> = Result<T, String>;

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultData {
    pub entries: Vec<SecretEntry>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub group: String,
    pub icon: String,
    #[serde(default = "default_secret_color_string")]
    pub color: String,
    #[serde(rename = "custom_fields")]
    pub custom_fields: Vec<CustomField>,
    #[serde(rename = "password_history")]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(rename = "change_history")]
    pub change_history: Vec<EntryChangeRecord>,
    pub favorite: bool,
    #[serde(rename = "created_at", deserialize_with = "deserialize_time_value")]
    pub created_at: String,
    #[serde(rename = "updated_at", deserialize_with = "deserialize_time_value")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    #[serde(rename = "changed_at")]
    pub changed_at: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EntryChangeRecord {
    #[serde(rename = "changed_at")]
    pub changed_at: i64,
    pub action: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    #[serde(rename = "entries_count")]
    pub entries_count: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    #[serde(rename = "imported_count")]
    pub imported_count: usize,
    #[serde(rename = "skipped_count")]
    pub skipped_count: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub vault: VaultData,
    pub summary: ImportSummary,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WindowsUnlockResult {
    pub vault: VaultData,
    pub master_password: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub source: String,
    pub detected_format: String,
    pub total_count: usize,
    pub sample_titles: Vec<String>,
    pub items: Vec<ImportPreviewItem>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewItem {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedPassword {
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BridgePairPin {
    pub pin: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupItem {
    pub path: String,
    #[serde(rename = "created_at")]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RecoverySettings {
    #[serde(default)]
    pub hint: String,
    #[serde(default, alias = "securityQuestions")]
    pub security_questions: Vec<SecurityQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SecurityQuestion {
    #[serde(default)]
    pub question: String,
    #[serde(default, alias = "answerHint")]
    pub answer_hint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub group: String,
    pub icon: String,
    pub color: String,
    #[serde(rename = "custom_fields")]
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEntryUpdateInput {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub group: String,
    pub icon: String,
    pub color: String,
    #[serde(rename = "custom_fields")]
    pub custom_fields: Vec<CustomField>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGenerationOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    entry: SecretEntryInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEntryArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    entry: SecretEntryUpdateInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteEntryArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    entry_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    group: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeMasterPasswordArgs<'a> {
    vault_path: &'a str,
    current_master_password: &'a str,
    new_master_password: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportKeePassArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    keepass_path: &'a str,
    keepass_password: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportCsvArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    csv_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewImportArgs<'a> {
    source_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportExternalArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    source_path: &'a str,
    source_password: &'a str,
    options: Option<ImportExternalOptions>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportExternalOptions {
    pub selected_indices: Option<Vec<usize>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportCsvArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    csv_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportEncryptedArgs<'a> {
    vault_path: &'a str,
    export_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportEncryptedWithPasswordArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    export_password: &'a str,
    export_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupListArgs<'a> {
    vault_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreBackupArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    backup_path: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryArgs<'a> {
    vault_path: &'a str,
    master_password: &'a str,
    recovery: RecoverySettings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordArgs {
    options: Option<PasswordGenerationOptions>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClipboardArgs<'a> {
    value: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenUrlArgs<'a> {
    url: &'a str,
}

#[derive(Serialize)]
struct EmptyArgs {}

pub async fn create_vault(vault_path: &str, master_password: &str) -> ApiResult<VaultSummary> {
    call(
        "create_vault",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn unlock_vault(vault_path: &str, master_password: &str) -> ApiResult<VaultData> {
    call(
        "unlock_vault",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn unlock_vault_with_windows(vault_path: &str) -> ApiResult<WindowsUnlockResult> {
    call("unlock_vault_with_windows", &BackupListArgs { vault_path }).await
}

pub async fn enable_windows_unlock(vault_path: &str, master_password: &str) -> ApiResult<()> {
    call(
        "enable_windows_unlock",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn disable_windows_unlock(vault_path: &str) -> ApiResult<()> {
    call("disable_windows_unlock", &BackupListArgs { vault_path }).await
}

pub async fn is_windows_unlock_enabled(vault_path: &str) -> ApiResult<bool> {
    call("is_windows_unlock_enabled", &BackupListArgs { vault_path }).await
}

pub async fn list_entries(vault_path: &str, master_password: &str) -> ApiResult<Vec<SecretEntry>> {
    call(
        "list_entries",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn add_entry(
    vault_path: &str,
    master_password: &str,
    entry: SecretEntryInput,
) -> ApiResult<VaultData> {
    call(
        "add_entry",
        &EntryArgs {
            vault_path,
            master_password,
            entry,
        },
    )
    .await
}

pub async fn update_entry(
    vault_path: &str,
    master_password: &str,
    entry: SecretEntryUpdateInput,
) -> ApiResult<VaultData> {
    call(
        "update_entry",
        &UpdateEntryArgs {
            vault_path,
            master_password,
            entry,
        },
    )
    .await
}

pub async fn delete_entry(
    vault_path: &str,
    master_password: &str,
    entry_id: &str,
) -> ApiResult<VaultData> {
    call(
        "delete_entry",
        &DeleteEntryArgs {
            vault_path,
            master_password,
            entry_id,
        },
    )
    .await
}

pub async fn create_group(
    vault_path: &str,
    master_password: &str,
    group: &str,
) -> ApiResult<VaultData> {
    call(
        "create_group",
        &CreateGroupArgs {
            vault_path,
            master_password,
            group,
        },
    )
    .await
}

pub async fn change_master_password(
    vault_path: &str,
    current_master_password: &str,
    new_master_password: &str,
) -> ApiResult<VaultSummary> {
    call(
        "change_master_password",
        &ChangeMasterPasswordArgs {
            vault_path,
            current_master_password,
            new_master_password,
        },
    )
    .await
}

pub async fn import_keepass_vault(
    vault_path: &str,
    master_password: &str,
    keepass_path: &str,
    keepass_password: &str,
) -> ApiResult<ImportResult> {
    call(
        "import_keepass_vault",
        &ImportKeePassArgs {
            vault_path,
            master_password,
            keepass_path,
            keepass_password,
        },
    )
    .await
}

pub async fn import_csv_vault(
    vault_path: &str,
    master_password: &str,
    csv_path: &str,
) -> ApiResult<ImportResult> {
    call(
        "import_csv_vault",
        &ImportCsvArgs {
            vault_path,
            master_password,
            csv_path,
        },
    )
    .await
}

pub async fn preview_import_source(source_path: &str) -> ApiResult<ImportPreview> {
    call("preview_import_source", &PreviewImportArgs { source_path }).await
}

pub async fn import_external_vault(
    vault_path: &str,
    master_password: &str,
    source_path: &str,
    source_password: &str,
    options: Option<ImportExternalOptions>,
) -> ApiResult<ImportResult> {
    call(
        "import_external_vault",
        &ImportExternalArgs {
            vault_path,
            master_password,
            source_path,
            source_password,
            options,
        },
    )
    .await
}

pub async fn export_vault_csv(
    vault_path: &str,
    master_password: &str,
    csv_path: &str,
) -> ApiResult<usize> {
    call(
        "export_vault_csv",
        &ExportCsvArgs {
            vault_path,
            master_password,
            csv_path,
        },
    )
    .await
}

pub async fn export_vault_encrypted(vault_path: &str, export_path: &str) -> ApiResult<()> {
    call(
        "export_vault_encrypted",
        &ExportEncryptedArgs {
            vault_path,
            export_path,
        },
    )
    .await
}

pub async fn export_vault_encrypted_with_password(
    vault_path: &str,
    master_password: &str,
    export_password: &str,
    export_path: &str,
) -> ApiResult<()> {
    call(
        "export_vault_encrypted_with_password",
        &ExportEncryptedWithPasswordArgs {
            vault_path,
            master_password,
            export_password,
            export_path,
        },
    )
    .await
}

pub async fn list_vault_backups(vault_path: &str) -> ApiResult<Vec<BackupItem>> {
    call("list_vault_backups", &BackupListArgs { vault_path }).await
}

pub async fn restore_vault_backup(
    vault_path: &str,
    master_password: &str,
    backup_path: &str,
) -> ApiResult<VaultData> {
    call(
        "restore_vault_backup",
        &RestoreBackupArgs {
            vault_path,
            master_password,
            backup_path,
        },
    )
    .await
}

pub async fn get_recovery_settings(
    vault_path: &str,
    master_password: &str,
) -> ApiResult<RecoverySettings> {
    call(
        "get_recovery_settings",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn update_recovery_settings(
    vault_path: &str,
    master_password: &str,
    recovery: RecoverySettings,
) -> ApiResult<RecoverySettings> {
    call(
        "update_recovery_settings",
        &RecoveryArgs {
            vault_path,
            master_password,
            recovery,
        },
    )
    .await
}

pub async fn generate_password(
    options: Option<PasswordGenerationOptions>,
) -> ApiResult<GeneratedPassword> {
    call("generate_password", &PasswordArgs { options }).await
}

pub async fn copy_secret_to_clipboard(value: &str) -> ApiResult<()> {
    call("copy_secret_to_clipboard", &ClipboardArgs { value }).await
}

pub async fn pick_vault_file() -> ApiResult<Option<String>> {
    call("pick_vault_file", &EmptyArgs {}).await
}

pub async fn choose_vault_save_path() -> ApiResult<Option<String>> {
    call("choose_vault_save_path", &EmptyArgs {}).await
}

pub async fn pick_import_file() -> ApiResult<Option<String>> {
    call("pick_import_file", &EmptyArgs {}).await
}

pub async fn choose_export_csv_path() -> ApiResult<Option<String>> {
    call("choose_export_csv_path", &EmptyArgs {}).await
}

pub async fn choose_export_encrypted_path() -> ApiResult<Option<String>> {
    call("choose_export_encrypted_path", &EmptyArgs {}).await
}

pub async fn pick_backup_file() -> ApiResult<Option<String>> {
    call("pick_backup_file", &EmptyArgs {}).await
}

pub async fn get_default_vault_path() -> ApiResult<String> {
    call("get_default_vault_path", &EmptyArgs {}).await
}

pub async fn get_startup_vault_path() -> ApiResult<Option<String>> {
    call("get_startup_vault_path", &EmptyArgs {}).await
}

pub async fn create_bridge_pair_pin() -> ApiResult<BridgePairPin> {
    call("create_bridge_pair_pin", &EmptyArgs {}).await
}

pub async fn set_bridge_active_session(vault_path: &str, master_password: &str) -> ApiResult<()> {
    call(
        "set_bridge_active_session",
        &VaultArgs {
            vault_path,
            master_password,
        },
    )
    .await
}

pub async fn clear_bridge_active_session() -> ApiResult<()> {
    call("clear_bridge_active_session", &EmptyArgs {}).await
}

pub async fn open_url(url: &str) -> ApiResult<()> {
    call("open_url", &OpenUrlArgs { url }).await
}

async fn call<T, R>(command: &str, args: &T) -> ApiResult<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let args = serde_wasm_bindgen::to_value(args).map_err(|error| error.to_string())?;
    let value = invoke(command, args).await.map_err(js_value_to_string)?;

    serde_wasm_bindgen::from_value(value).map_err(|error| error.to_string())
}

fn js_value_to_string(value: JsValue) -> String {
    value
        .as_string()
        .unwrap_or_else(|| "No se pudo completar la operación.".to_string())
}

fn default_secret_color_string() -> String {
    "#6366F1".to_string()
}

fn deserialize_time_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimeValue {
        Text(String),
        Parts((i32, u16, u8, u8, u8, u32, i8, i8, i8)),
    }

    match TimeValue::deserialize(deserializer)? {
        TimeValue::Text(value) => Ok(value),
        TimeValue::Parts((year, ordinal, hour, minute, second, _nano, _oh, _om, _os)) => Ok(
            format!("{year:04}-{:03}T{hour:02}:{minute:02}:{second:02}Z", ordinal),
        ),
    }
}
