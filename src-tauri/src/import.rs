use std::{collections::HashMap, fs::File, io::Read, path::Path};

use keepass::{
    db::{fields, EntryRef},
    Database, DatabaseKey,
};

use crate::{
    error::{VaultError, VaultResult},
    models::{
        CustomField, ImportPreview, ImportPreviewItem, SecretEntryInput, DEFAULT_COLOR,
        DEFAULT_GROUP, DEFAULT_ICON,
    },
};

const DETECT_KEEPASS: &str = "keepass";
const DETECT_BITWARDEN_CSV: &str = "bitwarden_csv";
const DETECT_ONEPASSWORD_CSV: &str = "1password_csv";
const DETECT_STANDARD_CSV: &str = "standard_csv";
const DETECT_ONEPASSWORD_1PIF: &str = "1password_1pif";
const DETECT_ONEPASSWORD_1PUX: &str = "1password_1pux";

pub fn read_keepass_entries(
    path: impl AsRef<Path>,
    keepass_password: &str,
) -> VaultResult<Vec<SecretEntryInput>> {
    let mut source = File::open(path)?;
    let key = DatabaseKey::default().with_password(keepass_password);
    let database = Database::open(&mut source, key)
        .map_err(|error| VaultError::Validation(format!("No se pudo abrir KeePass: {error}")))?;

    Ok(database
        .iter_all_entries()
        .map(|entry| keepass_entry_to_secret(entry))
        .collect())
}

pub fn read_csv_entries(path: impl AsRef<Path>) -> VaultResult<Vec<SecretEntryInput>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|error| VaultError::Validation(format!("No se pudo abrir CSV: {error}")))?;
    let headers = reader
        .headers()
        .map_err(|error| VaultError::Validation(format!("CSV inválido: {error}")))?
        .iter()
        .map(normalize_header)
        .collect::<Vec<_>>();

    let mut entries = Vec::new();
    for result in reader.records() {
        let record =
            result.map_err(|error| VaultError::Validation(format!("CSV inválido: {error}")))?;
        let mut row = HashMap::<String, String>::new();
        for (index, value) in record.iter().enumerate() {
            if let Some(header) = headers.get(index) {
                row.insert(header.clone(), value.trim().to_string());
            }
        }
        if let Some(entry) = csv_row_to_secret(&row) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub fn detect_and_preview(path: impl AsRef<Path>) -> VaultResult<ImportPreview> {
    let path = path.as_ref();
    let detected = detect_source(path)?;
    let entries = read_source_entries(path, &detected, "")?;
    let sample_titles = entries
        .iter()
        .take(5)
        .map(|entry| entry.title.clone())
        .collect::<Vec<_>>();

    Ok(ImportPreview {
        source: path.to_string_lossy().to_string(),
        detected_format: detected.to_string(),
        total_count: entries.len(),
        sample_titles,
        items: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| ImportPreviewItem {
                index,
                title: entry.title.clone(),
                username: entry.username.clone(),
                url: entry.url.clone(),
            })
            .collect(),
    })
}

pub fn read_source_entries(
    path: impl AsRef<Path>,
    detected_format: &str,
    source_password: &str,
) -> VaultResult<Vec<SecretEntryInput>> {
    match detected_format {
        DETECT_KEEPASS => read_keepass_entries(path, source_password),
        DETECT_BITWARDEN_CSV | DETECT_ONEPASSWORD_CSV | DETECT_STANDARD_CSV => {
            read_csv_entries(path)
        }
        DETECT_ONEPASSWORD_1PIF => read_1pif_entries(path),
        DETECT_ONEPASSWORD_1PUX => read_1pux_entries(path),
        _ => Err(VaultError::Validation(
            "Formato de importación no soportado".to_string(),
        )),
    }
}

pub fn detect_source(path: impl AsRef<Path>) -> VaultResult<&'static str> {
    let path = path.as_ref();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_lowercase();

    match extension.as_str() {
        "kdbx" | "kdb" => return Ok(DETECT_KEEPASS),
        "1pif" => return Ok(DETECT_ONEPASSWORD_1PIF),
        "1pux" => return Ok(DETECT_ONEPASSWORD_1PUX),
        "csv" => {
            let headers = read_csv_headers(path)?;
            if headers
                .iter()
                .any(|header| header == "login username" || header == "login password")
            {
                return Ok(DETECT_BITWARDEN_CSV);
            }
            if headers
                .iter()
                .any(|header| header == "vault" || header == "type" || header == "otpauth")
            {
                return Ok(DETECT_ONEPASSWORD_CSV);
            }
            return Ok(DETECT_STANDARD_CSV);
        }
        _ => {}
    }

    Err(VaultError::Validation(
        "No se pudo detectar el formato del archivo".to_string(),
    ))
}

fn keepass_entry_to_secret(entry: EntryRef<'_>) -> SecretEntryInput {
    let title = field_value(&entry, fields::TITLE);
    let username = field_value(&entry, fields::USERNAME);
    let password = field_value(&entry, fields::PASSWORD);
    let url = field_value(&entry, fields::URL);
    let notes = field_value(&entry, fields::NOTES);

    SecretEntryInput {
        title: fallback_title(&title, &username, &url),
        username,
        password,
        url,
        notes,
        group: keepass_group_name(&entry),
        icon: DEFAULT_ICON.to_string(),
        color: DEFAULT_COLOR.to_string(),
        custom_fields: keepass_custom_fields(&entry),
    }
}

fn field_value(entry: &EntryRef<'_>, field: &str) -> String {
    entry
        .get(field)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

fn fallback_title(title: &str, username: &str, url: &str) -> String {
    if !title.trim().is_empty() {
        return title.trim().to_string();
    }

    if !url.trim().is_empty() {
        return url.trim().to_string();
    }

    if !username.trim().is_empty() {
        return username.trim().to_string();
    }

    "Entrada KeePass".to_string()
}

fn keepass_group_name(entry: &EntryRef<'_>) -> String {
    let group = entry.parent();

    if group.parent().is_none() || group.name.trim().is_empty() {
        DEFAULT_GROUP.to_string()
    } else {
        group.name.trim().to_string()
    }
}

fn keepass_custom_fields(entry: &EntryRef<'_>) -> Vec<CustomField> {
    let mut keys = entry.fields.keys().cloned().collect::<Vec<_>>();
    keys.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));

    keys.into_iter()
        .filter(|key| !is_standard_keepass_field(key))
        .filter_map(|key| {
            let value = field_value(entry, &key);

            if value.is_empty() {
                None
            } else {
                Some(CustomField { label: key, value })
            }
        })
        .collect()
}

fn is_standard_keepass_field(field: &str) -> bool {
    fields::KNOWN_FIELDS
        .iter()
        .chain(std::iter::once(&fields::OTP))
        .any(|known| known.eq_ignore_ascii_case(field))
}

fn csv_row_to_secret(row: &HashMap<String, String>) -> Option<SecretEntryInput> {
    let title = pick_csv_value(row, &["title", "name", "item name", "login_uri"]);
    let username = pick_csv_value(row, &["username", "login_username", "user", "email"]);
    let password = pick_csv_value(row, &["password", "login_password"]);
    let url = pick_csv_value(row, &["url", "login_uri", "website"]);
    let notes = pick_csv_value(row, &["notes", "note"]);
    let group = pick_csv_value(row, &["group", "folder", "category"]);

    if title.trim().is_empty() && password.trim().is_empty() {
        return None;
    }

    Some(SecretEntryInput {
        title: fallback_title(&title, &username, &url),
        username,
        password,
        url,
        notes,
        group: if group.trim().is_empty() {
            DEFAULT_GROUP.to_string()
        } else {
            group
        },
        icon: DEFAULT_ICON.to_string(),
        color: DEFAULT_COLOR.to_string(),
        custom_fields: Vec::new(),
    })
}

fn pick_csv_value(row: &HashMap<String, String>, aliases: &[&str]) -> String {
    aliases
        .iter()
        .find_map(|alias| row.get(&normalize_header(alias)).cloned())
        .unwrap_or_default()
}

fn normalize_header(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .replace('_', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_csv_headers(path: &Path) -> VaultResult<Vec<String>> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|error| VaultError::Validation(format!("No se pudo abrir CSV: {error}")))?;
    let headers = reader
        .headers()
        .map_err(|error| VaultError::Validation(format!("CSV inválido: {error}")))?
        .iter()
        .map(normalize_header)
        .collect::<Vec<_>>();
    Ok(headers)
}

fn read_1pif_entries(path: impl AsRef<Path>) -> VaultResult<Vec<SecretEntryInput>> {
    let content = std::fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(entry) = onepassword_value_to_entry(&value) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn read_1pux_entries(path: impl AsRef<Path>) -> VaultResult<Vec<SecretEntryInput>> {
    let file = File::open(path)?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|error| VaultError::Validation(format!("1PUX inválido: {error}")))?;

    for index in 0..zip.len() {
        let mut file = zip
            .by_index(index)
            .map_err(|error| VaultError::Validation(format!("1PUX inválido: {error}")))?;
        let name = file.name().to_lowercase();
        if name.ends_with(".1pif") || name.ends_with("export.data") {
            let mut content = String::new();
            file.read_to_string(&mut content).map_err(|error| {
                VaultError::Validation(format!("No se pudo leer contenido 1PUX: {error}"))
            })?;
            return read_1pif_entries_from_content(&content);
        }
    }

    Err(VaultError::Validation(
        "No se encontró contenido importable dentro del 1PUX".to_string(),
    ))
}

fn read_1pif_entries_from_content(content: &str) -> VaultResult<Vec<SecretEntryInput>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(entry) = onepassword_value_to_entry(&value) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn onepassword_value_to_entry(value: &serde_json::Value) -> Option<SecretEntryInput> {
    let title = value
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let notes = value
        .get("notesPlain")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let mut username = String::new();
    let mut password = String::new();
    let mut url = String::new();

    if let Some(fields) = value.get("fields").and_then(|v| v.as_array()) {
        for field in fields {
            let designation = field
                .get("designation")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            let name = field
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            let field_value = field
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if username.is_empty() && (designation == "username" || name.contains("user")) {
                username = field_value.clone();
            }
            if password.is_empty()
                && (designation == "password" || name.contains("password") || name == "pass")
            {
                password = field_value.clone();
            }
            if url.is_empty() && (name.contains("url") || name.contains("website")) {
                url = field_value;
            }
        }
    }

    if password.is_empty() {
        return None;
    }

    Some(SecretEntryInput {
        title: fallback_title(&title, &username, &url),
        username,
        password,
        url,
        notes,
        group: DEFAULT_GROUP.to_string(),
        icon: DEFAULT_ICON.to_string(),
        color: DEFAULT_COLOR.to_string(),
        custom_fields: Vec::new(),
    })
}
