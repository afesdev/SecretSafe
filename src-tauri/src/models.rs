use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub const VAULT_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_GROUP: &str = "General";
pub const DEFAULT_ICON: &str = "auto";
pub const DEFAULT_COLOR: &str = "#6366f1";
pub const PASSWORD_HISTORY_LIMIT: usize = 10;
pub const CHANGE_HISTORY_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u16,
    pub entries: Vec<SecretEntry>,
    #[serde(default = "default_groups")]
    pub groups: Vec<String>,
    #[serde(default)]
    pub recovery: RecoverySettings,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl VaultData {
    pub fn empty() -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            version: VAULT_FORMAT_VERSION,
            entries: Vec::new(),
            groups: default_groups(),
            recovery: RecoverySettings::default(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_icon")]
    pub icon: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    #[serde(default)]
    pub change_history: Vec<EntryChangeRecord>,
    pub favorite: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl SecretEntry {
    pub fn from_input(input: SecretEntryInput) -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            id: Uuid::new_v4(),
            title: input.title,
            username: input.username,
            password: input.password,
            url: input.url,
            notes: input.notes,
            group: normalize_group(input.group),
            icon: normalize_icon(input.icon),
            color: normalize_color(input.color),
            custom_fields: normalize_custom_fields(input.custom_fields),
            password_history: Vec::new(),
            change_history: vec![EntryChangeRecord {
                changed_at: now.unix_timestamp(),
                action: "created".to_string(),
                details: "Secreto creado".to_string(),
            }],
            favorite: false,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryChangeRecord {
    pub changed_at: i64,
    pub action: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoverySettings {
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub security_questions: Vec<SecurityQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntryInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_icon")]
    pub icon: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntryUpdateInput {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_icon")]
    pub icon: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    pub favorite: bool,
}

pub fn default_group() -> String {
    DEFAULT_GROUP.to_string()
}

pub fn default_groups() -> Vec<String> {
    vec![default_group()]
}

pub fn default_icon() -> String {
    DEFAULT_ICON.to_string()
}

pub fn default_color() -> String {
    DEFAULT_COLOR.to_string()
}

pub fn normalize_group(group: String) -> String {
    let group = group.trim();

    if group.is_empty() {
        default_group()
    } else {
        group.to_string()
    }
}

pub fn normalize_icon(icon: String) -> String {
    let icon = icon.trim();

    if icon.is_empty() {
        default_icon()
    } else {
        icon.to_string()
    }
}

pub fn normalize_color(color: String) -> String {
    let color = color.trim();
    if color.is_empty() {
        return default_color();
    }

    let normalized = if color.starts_with('#') {
        color.to_string()
    } else {
        format!("#{color}")
    };
    let hex = normalized.trim_start_matches('#');
    let valid = hex.len() == 6 && hex.chars().all(|ch| ch.is_ascii_hexdigit());

    if valid {
        format!("#{}", hex.to_uppercase())
    } else {
        default_color()
    }
}

pub fn normalize_custom_fields(fields: Vec<CustomField>) -> Vec<CustomField> {
    fields
        .into_iter()
        .filter_map(|field| {
            let label = field.label.trim().to_string();
            let value = field.value.trim().to_string();

            if label.is_empty() && value.is_empty() {
                None
            } else {
                Some(CustomField { label, value })
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGenerationOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
}

impl Default for PasswordGenerationOptions {
    fn default() -> Self {
        Self {
            length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPassword {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSummary {
    pub version: u16,
    pub entries_count: usize,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl From<&VaultData> for VaultSummary {
    fn from(vault: &VaultData) -> Self {
        Self {
            version: vault.version,
            entries_count: vault.entries.len(),
            created_at: vault.created_at,
            updated_at: vault.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    pub imported_count: usize,
    pub skipped_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub source: String,
    pub detected_format: String,
    pub total_count: usize,
    pub sample_titles: Vec<String>,
    pub items: Vec<ImportPreviewItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewItem {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub vault: VaultData,
    pub summary: ImportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsUnlockResult {
    pub vault: VaultData,
    pub master_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgePairPin {
    pub pin: String,
    pub expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupItem {
    pub path: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub version: u16,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub algorithm: String,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}
