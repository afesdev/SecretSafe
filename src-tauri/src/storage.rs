use std::{
    fs,
    path::{Path, PathBuf},
};

use tauri::{AppHandle, Manager};

use crate::{
    error::VaultResult,
    models::{BackupItem, VaultEnvelope},
};

const DEFAULT_VAULT_FILE: &str = "secretsafe.vault";
const BACKUP_RETENTION_LIMIT: usize = 100;

pub fn read_envelope(path: impl AsRef<Path>) -> VaultResult<VaultEnvelope> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_envelope(path: impl AsRef<Path>, envelope: &VaultEnvelope) -> VaultResult<()> {
    let path = path.as_ref();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bytes = serde_json::to_vec_pretty(envelope)?;
    fs::write(path, bytes)?;

    Ok(())
}

pub fn backup_existing_vault(path: impl AsRef<Path>) -> VaultResult<Option<PathBuf>> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(None);
    }

    let backup_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".backups");
    fs::create_dir_all(&backup_dir)?;

    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("secretsafe");
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let backup_path = backup_dir.join(format!("{stem}-{timestamp}.vault"));

    fs::copy(path, &backup_path)?;
    prune_old_backups(&backup_dir, BACKUP_RETENTION_LIMIT)?;

    Ok(Some(backup_path))
}

pub fn list_backups(path: impl AsRef<Path>) -> VaultResult<Vec<BackupItem>> {
    let path = path.as_ref();
    let backup_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".backups");

    if !backup_dir.exists() {
        return Ok(Vec::new());
    }

    let mut items = fs::read_dir(&backup_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("vault"))
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_stem()?.to_str()?;
            let timestamp = name.rsplit('-').next()?.parse::<i64>().ok()?;
            Some(BackupItem {
                path: path.to_string_lossy().to_string(),
                created_at: timestamp,
            })
        })
        .collect::<Vec<_>>();

    items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(items)
}

pub fn restore_backup(
    vault_path: impl AsRef<Path>,
    backup_path: impl AsRef<Path>,
) -> VaultResult<()> {
    let vault_path = vault_path.as_ref();
    let backup_path = backup_path.as_ref();

    if !backup_path.exists() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotFound, "Backup no encontrado").into(),
        );
    }

    if vault_path.exists() {
        let _ = backup_existing_vault(vault_path)?;
    }
    fs::copy(backup_path, vault_path)?;
    Ok(())
}

pub fn export_encrypted_vault(
    vault_path: impl AsRef<Path>,
    export_path: impl AsRef<Path>,
) -> VaultResult<()> {
    let vault_path = vault_path.as_ref();
    let export_path = export_path.as_ref();

    if let Some(parent) = export_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(vault_path, export_path)?;
    Ok(())
}

fn prune_old_backups(backup_dir: &Path, keep: usize) -> VaultResult<()> {
    let mut backups = fs::read_dir(backup_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("vault"))
        .collect::<Vec<_>>();

    backups.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .map(|elapsed| std::cmp::Reverse(elapsed.as_secs()))
            .unwrap_or(std::cmp::Reverse(0))
    });

    if backups.len() <= keep {
        return Ok(());
    }

    let remove_count = backups.len() - keep;
    for entry in backups.into_iter().take(remove_count) {
        let _ = fs::remove_file(entry.path());
    }

    Ok(())
}

pub fn default_vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join(DEFAULT_VAULT_FILE))
        .map_err(|error| error.to_string())
}

pub fn normalize_vault_path(app: &AppHandle, vault_path: String) -> Result<PathBuf, String> {
    let path = PathBuf::from(vault_path.trim());

    if path.as_os_str().is_empty() {
        return default_vault_path(app);
    }

    if path.is_relative() {
        return app
            .path()
            .app_data_dir()
            .map(|app_data| app_data.join(path))
            .map_err(|error| error.to_string());
    }

    Ok(path)
}
