use std::{fs::File, path::Path};

use crate::{
    crypto::{decrypt_payload, default_kdf_params, encrypt_payload},
    error::{VaultError, VaultResult},
    import,
    models::{
        normalize_color, normalize_custom_fields, normalize_group, normalize_icon, BackupItem,
        EntryChangeRecord, ImportPreview, ImportSummary, PasswordHistoryEntry, RecoverySettings,
        SecretEntry, SecretEntryInput, SecretEntryUpdateInput, SecurityQuestion, VaultData,
        VaultEnvelope, VaultSummary, CHANGE_HISTORY_LIMIT, DEFAULT_GROUP, PASSWORD_HISTORY_LIMIT,
        VAULT_FORMAT_VERSION,
    },
    storage::{
        backup_existing_vault, export_encrypted_vault, list_backups, read_envelope, restore_backup,
        write_envelope,
    },
};

pub fn create_vault(path: impl AsRef<Path>, master_password: &str) -> VaultResult<VaultSummary> {
    validate_master_password(master_password)?;

    let vault = VaultData::empty();
    let envelope = seal_vault(master_password, &vault)?;

    write_envelope(path, &envelope)?;

    Ok(VaultSummary::from(&vault))
}

pub fn unlock_vault(path: impl AsRef<Path>, master_password: &str) -> VaultResult<VaultData> {
    validate_master_password(master_password)?;

    let envelope = read_envelope(path)?;
    open_envelope(master_password, &envelope)
}

pub fn add_entry(
    path: impl AsRef<Path>,
    master_password: &str,
    input: SecretEntryInput,
) -> VaultResult<VaultData> {
    validate_entry_input(&input)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;

    let entry = SecretEntry::from_input(input);
    add_group_if_missing(&mut vault, &entry.group);
    vault.entries.push(entry);
    vault.touch();

    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;

    Ok(vault)
}

pub fn update_entry(
    path: impl AsRef<Path>,
    master_password: &str,
    input: SecretEntryUpdateInput,
) -> VaultResult<VaultData> {
    validate_update_input(&input)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    let entry = vault
        .entries
        .iter_mut()
        .find(|entry| entry.id == input.id)
        .ok_or_else(|| {
            VaultError::Validation("No se encontró el secreto solicitado".to_string())
        })?;

    let now = time::OffsetDateTime::now_utc();
    let update_details = build_update_details(entry, &input);
    if entry.password != input.password {
        entry.password_history.insert(
            0,
            PasswordHistoryEntry {
                password: entry.password.clone(),
                changed_at: now.unix_timestamp(),
            },
        );
        entry.password_history.truncate(PASSWORD_HISTORY_LIMIT);
    }

    entry.title = input.title;
    entry.username = input.username;
    entry.password = input.password;
    entry.url = input.url;
    entry.notes = input.notes;
    let group = normalize_group(input.group);
    entry.group = group.clone();
    entry.icon = normalize_icon(input.icon);
    entry.color = normalize_color(input.color);
    entry.custom_fields = normalize_custom_fields(input.custom_fields);
    entry.favorite = input.favorite;
    push_change_record(entry, now.unix_timestamp(), "updated", update_details);
    entry.updated_at = now;
    add_group_if_missing(&mut vault, &group);
    vault.touch();

    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;

    Ok(vault)
}

pub fn delete_entry(
    path: impl AsRef<Path>,
    master_password: &str,
    entry_id: uuid::Uuid,
) -> VaultResult<VaultData> {
    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    let previous_len = vault.entries.len();

    vault.entries.retain(|entry| entry.id != entry_id);

    if vault.entries.len() == previous_len {
        return Err(VaultError::Validation(
            "No se encontró el secreto solicitado".to_string(),
        ));
    }

    vault.touch();

    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;

    Ok(vault)
}

pub fn save_vault(
    path: impl AsRef<Path>,
    master_password: &str,
    mut vault: VaultData,
) -> VaultResult<VaultSummary> {
    validate_master_password(master_password)?;
    validate_vault_version(vault.version)?;

    let path = path.as_ref();
    normalize_vault(&mut vault);
    vault.touch();

    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;

    Ok(VaultSummary::from(&vault))
}

pub fn create_group(
    path: impl AsRef<Path>,
    master_password: &str,
    group: String,
) -> VaultResult<VaultData> {
    let group = normalize_group(group);
    validate_group_name(&group)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    add_group_if_missing(&mut vault, &group);
    vault.touch();

    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;

    Ok(vault)
}

pub fn change_master_password(
    path: impl AsRef<Path>,
    current_master_password: &str,
    new_master_password: &str,
) -> VaultResult<VaultSummary> {
    validate_master_password(current_master_password)?;
    validate_master_password(new_master_password)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, current_master_password)?;
    vault.touch();
    let envelope = seal_vault(new_master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;
    Ok(VaultSummary::from(&vault))
}

pub fn import_keepass_vault(
    path: impl AsRef<Path>,
    master_password: &str,
    keepass_path: impl AsRef<Path>,
    keepass_password: &str,
) -> VaultResult<(VaultData, ImportSummary)> {
    validate_master_password(master_password)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    let entries = import::read_keepass_entries(keepass_path, keepass_password)?;
    let mut summary = ImportSummary {
        imported_count: 0,
        skipped_count: 0,
    };

    for input in entries {
        if validate_entry_input(&input).is_err() || contains_duplicate_entry(&vault, &input) {
            summary.skipped_count += 1;
            continue;
        }

        let entry = SecretEntry::from_input(input);
        add_group_if_missing(&mut vault, &entry.group);
        vault.entries.push(entry);
        summary.imported_count += 1;
    }

    if summary.imported_count > 0 {
        vault.touch();
        let envelope = seal_vault(master_password, &vault)?;
        backup_existing_vault(path)?;
        write_envelope(path, &envelope)?;
    }

    Ok((vault, summary))
}

pub fn import_csv_vault(
    path: impl AsRef<Path>,
    master_password: &str,
    csv_path: impl AsRef<Path>,
) -> VaultResult<(VaultData, ImportSummary)> {
    validate_master_password(master_password)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    let entries = import::read_csv_entries(csv_path)?;
    let mut summary = ImportSummary {
        imported_count: 0,
        skipped_count: 0,
    };

    for input in entries {
        if validate_entry_input(&input).is_err() || contains_duplicate_entry(&vault, &input) {
            summary.skipped_count += 1;
            continue;
        }

        let entry = SecretEntry::from_input(input);
        add_group_if_missing(&mut vault, &entry.group);
        vault.entries.push(entry);
        summary.imported_count += 1;
    }

    if summary.imported_count > 0 {
        vault.touch();
        let envelope = seal_vault(master_password, &vault)?;
        backup_existing_vault(path)?;
        write_envelope(path, &envelope)?;
    }

    Ok((vault, summary))
}

pub fn preview_import_source(source_path: impl AsRef<Path>) -> VaultResult<ImportPreview> {
    import::detect_and_preview(source_path)
}

pub fn import_external_vault(
    path: impl AsRef<Path>,
    master_password: &str,
    source_path: impl AsRef<Path>,
    source_password: &str,
    selected_indices: Option<Vec<usize>>,
) -> VaultResult<(VaultData, ImportSummary)> {
    validate_master_password(master_password)?;

    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    let detected = import::detect_source(source_path.as_ref())?;
    let entries = import::read_source_entries(source_path, detected, source_password)?;
    let selected_indices = selected_indices.unwrap_or_default();
    let has_selection = !selected_indices.is_empty();
    let mut summary = ImportSummary {
        imported_count: 0,
        skipped_count: 0,
    };

    for (index, input) in entries.into_iter().enumerate() {
        if has_selection && !selected_indices.contains(&index) {
            summary.skipped_count += 1;
            continue;
        }
        if validate_entry_input(&input).is_err() || contains_duplicate_entry(&vault, &input) {
            summary.skipped_count += 1;
            continue;
        }
        let entry = SecretEntry::from_input(input);
        add_group_if_missing(&mut vault, &entry.group);
        vault.entries.push(entry);
        summary.imported_count += 1;
    }

    if summary.imported_count > 0 {
        vault.touch();
        let envelope = seal_vault(master_password, &vault)?;
        backup_existing_vault(path)?;
        write_envelope(path, &envelope)?;
    }

    Ok((vault, summary))
}

pub fn export_vault_csv(
    path: impl AsRef<Path>,
    master_password: &str,
    csv_path: impl AsRef<Path>,
) -> VaultResult<usize> {
    let vault = unlock_vault(path, master_password)?;

    let csv_path = csv_path.as_ref();
    let csv_path = if csv_path.extension().is_none() {
        std::borrow::Cow::Owned(csv_path.with_extension("csv"))
    } else {
        std::borrow::Cow::Borrowed(csv_path)
    };
    let csv_path = csv_path.as_ref();

    if let Some(parent) = csv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(csv_path)?;
    // UTF-8 BOM so Excel opens the file with correct encoding
    std::io::Write::write_all(&mut file, b"\xEF\xBB\xBF")?;

    let mut writer = csv::WriterBuilder::new().from_writer(file);
    writer
        .write_record(["title", "username", "password", "url", "notes", "group", "favorite"])
        .map_err(|e| VaultError::Validation(format!("No se pudo exportar CSV: {e}")))?;

    for entry in &vault.entries {
        writer
            .write_record([
                entry.title.as_str(),
                entry.username.as_str(),
                entry.password.as_str(),
                entry.url.as_str(),
                entry.notes.as_str(),
                entry.group.as_str(),
                if entry.favorite { "true" } else { "false" },
            ])
            .map_err(|e| VaultError::Validation(format!("No se pudo exportar CSV: {e}")))?;
    }

    let count = vault.entries.len();
    writer
        .into_inner()
        .map_err(|e| VaultError::Validation(format!("No se pudo finalizar el CSV: {}", e.error())))?;

    Ok(count)
}

pub fn export_vault_encrypted(
    path: impl AsRef<Path>,
    export_path: impl AsRef<Path>,
) -> VaultResult<()> {
    export_encrypted_vault(path, export_path)
}

pub fn export_vault_encrypted_with_password(
    path: impl AsRef<Path>,
    master_password: &str,
    export_password: &str,
    export_path: impl AsRef<Path>,
) -> VaultResult<()> {
    validate_master_password(master_password)?;
    validate_master_password(export_password)?;
    let vault = unlock_vault(path, master_password)?;
    let envelope = seal_vault(export_password, &vault)?;
    write_envelope(export_path, &envelope)?;
    Ok(())
}

pub fn list_vault_backups(path: impl AsRef<Path>) -> VaultResult<Vec<BackupItem>> {
    list_backups(path)
}

pub fn restore_vault_from_backup(
    path: impl AsRef<Path>,
    master_password: &str,
    backup_path: impl AsRef<Path>,
) -> VaultResult<VaultData> {
    restore_backup(path.as_ref(), backup_path)?;
    unlock_vault(path, master_password)
}

pub fn get_recovery_settings(
    path: impl AsRef<Path>,
    master_password: &str,
) -> VaultResult<RecoverySettings> {
    let vault = unlock_vault(path, master_password)?;
    Ok(vault.recovery)
}

pub fn update_recovery_settings(
    path: impl AsRef<Path>,
    master_password: &str,
    recovery: RecoverySettings,
) -> VaultResult<RecoverySettings> {
    validate_master_password(master_password)?;
    let path = path.as_ref();
    let mut vault = unlock_vault(path, master_password)?;
    vault.recovery = normalize_recovery_settings(recovery);
    vault.touch();
    let envelope = seal_vault(master_password, &vault)?;
    backup_existing_vault(path)?;
    write_envelope(path, &envelope)?;
    Ok(vault.recovery)
}

fn seal_vault(master_password: &str, vault: &VaultData) -> VaultResult<VaultEnvelope> {
    validate_vault_version(vault.version)?;

    let kdf = default_kdf_params();
    let payload = serde_json::to_vec(vault)?;
    let (cipher, payload) = encrypt_payload(master_password, &kdf, &payload)?;

    Ok(VaultEnvelope {
        version: VAULT_FORMAT_VERSION,
        kdf,
        cipher,
        payload,
    })
}

fn open_envelope(master_password: &str, envelope: &VaultEnvelope) -> VaultResult<VaultData> {
    validate_vault_version(envelope.version)?;

    let plaintext = decrypt_payload(
        master_password,
        &envelope.kdf,
        &envelope.cipher,
        &envelope.payload,
    )?;

    let mut vault: VaultData = serde_json::from_slice(&plaintext)?;
    validate_vault_version(vault.version)?;
    normalize_vault(&mut vault);

    Ok(vault)
}

fn validate_master_password(master_password: &str) -> VaultResult<()> {
    if master_password.trim().len() < 12 {
        return Err(VaultError::Validation(
            "La contraseña maestra debe tener al menos 12 caracteres".to_string(),
        ));
    }

    Ok(())
}

fn validate_entry_input(input: &SecretEntryInput) -> VaultResult<()> {
    if input.title.trim().is_empty() {
        return Err(VaultError::Validation(
            "El título del secreto es obligatorio".to_string(),
        ));
    }

    if input.password.is_empty() {
        return Err(VaultError::Validation(
            "La contraseña del secreto es obligatoria".to_string(),
        ));
    }

    Ok(())
}

fn validate_update_input(input: &SecretEntryUpdateInput) -> VaultResult<()> {
    validate_entry_input(&SecretEntryInput {
        title: input.title.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        url: input.url.clone(),
        notes: input.notes.clone(),
        group: input.group.clone(),
        icon: input.icon.clone(),
        color: input.color.clone(),
        custom_fields: input.custom_fields.clone(),
    })
}

fn validate_group_name(group: &str) -> VaultResult<()> {
    if group.trim().is_empty() {
        return Err(VaultError::Validation(
            "El nombre de la carpeta es obligatorio".to_string(),
        ));
    }

    Ok(())
}

fn normalize_vault(vault: &mut VaultData) {
    if vault.groups.is_empty() {
        vault.groups.push(DEFAULT_GROUP.to_string());
    }

    for entry in &mut vault.entries {
        entry.group = normalize_group(entry.group.clone());
        entry.icon = normalize_icon(entry.icon.clone());
        entry.color = normalize_color(entry.color.clone());
        entry.custom_fields = normalize_custom_fields(entry.custom_fields.clone());
        entry.password_history.truncate(PASSWORD_HISTORY_LIMIT);
        entry.change_history.truncate(CHANGE_HISTORY_LIMIT);
    }
    vault.recovery = normalize_recovery_settings(vault.recovery.clone());

    let entry_groups = vault
        .entries
        .iter()
        .map(|entry| entry.group.clone())
        .collect::<Vec<_>>();

    for group in entry_groups {
        add_group_if_missing(vault, &group);
    }

    vault.groups = vault
        .groups
        .iter()
        .map(|group| normalize_group(group.clone()))
        .fold(Vec::<String>::new(), |mut groups, group| {
            if !groups
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&group))
            {
                groups.push(group);
            }
            groups
        });

    vault
        .groups
        .sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
}

fn add_group_if_missing(vault: &mut VaultData, group: &str) {
    if !vault
        .groups
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(group))
    {
        vault.groups.push(group.to_string());
        vault
            .groups
            .sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    }
}

fn contains_duplicate_entry(vault: &VaultData, input: &SecretEntryInput) -> bool {
    vault.entries.iter().any(|entry| {
        same_text(&entry.title, &input.title)
            && same_text(&entry.username, &input.username)
            && same_text(&entry.url, &input.url)
    })
}

fn same_text(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

fn validate_vault_version(version: u16) -> VaultResult<()> {
    if version != VAULT_FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }

    Ok(())
}

fn build_update_details(entry: &SecretEntry, input: &SecretEntryUpdateInput) -> String {
    let mut changed = Vec::new();
    if !same_text(&entry.title, &input.title) {
        changed.push("titulo");
    }
    if !same_text(&entry.username, &input.username) {
        changed.push("usuario");
    }
    if entry.password != input.password {
        changed.push("password");
    }
    if !same_text(&entry.url, &input.url) {
        changed.push("url");
    }
    if !same_text(&entry.notes, &input.notes) {
        changed.push("notas");
    }
    if !same_text(&entry.group, &input.group) {
        changed.push("carpeta");
    }
    if !same_text(&entry.icon, &input.icon) {
        changed.push("icono");
    }
    if !same_text(&entry.color, &input.color) {
        changed.push("color");
    }
    if entry.favorite != input.favorite {
        changed.push("favorito");
    }
    if changed.is_empty() {
        "Sin cambios de contenido".to_string()
    } else {
        format!("Campos actualizados: {}", changed.join(", "))
    }
}

fn push_change_record(entry: &mut SecretEntry, changed_at: i64, action: &str, details: String) {
    entry.change_history.insert(
        0,
        EntryChangeRecord {
            changed_at,
            action: action.to_string(),
            details,
        },
    );
    entry.change_history.truncate(CHANGE_HISTORY_LIMIT);
}

fn normalize_recovery_settings(recovery: RecoverySettings) -> RecoverySettings {
    let hint = recovery.hint.trim().to_string();
    let security_questions = recovery
        .security_questions
        .into_iter()
        .filter_map(|item| {
            let question = item.question.trim().to_string();
            let answer_hint = item.answer_hint.trim().to_string();
            if question.is_empty() && answer_hint.is_empty() {
                None
            } else {
                Some(SecurityQuestion {
                    question,
                    answer_hint,
                })
            }
        })
        .take(5)
        .collect::<Vec<_>>();

    RecoverySettings {
        hint,
        security_questions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trip_requires_correct_password() {
        let password = "correct horse battery staple";
        let vault = VaultData::empty();
        let envelope = seal_vault(password, &vault).expect("vault should encrypt");

        let opened = open_envelope(password, &envelope).expect("password should decrypt vault");
        assert_eq!(opened.entries.len(), 0);

        let wrong_password = open_envelope("wrong horse battery staple", &envelope);
        assert!(matches!(wrong_password, Err(VaultError::InvalidPassword)));
    }
}
