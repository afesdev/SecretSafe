use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::{
    error::{VaultError, VaultResult},
    vault,
};

const WINDOWS_UNLOCK_FILE: &str = "windows-unlock.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WindowsUnlockEntry {
    vault_path: String,
    protected_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct WindowsUnlockStore {
    entries: Vec<WindowsUnlockEntry>,
}

pub fn enable_windows_unlock(
    app: &AppHandle,
    vault_path: impl AsRef<Path>,
    master_password: &str,
) -> VaultResult<()> {
    let vault_path = vault_path.as_ref();
    let _ = vault::unlock_vault(vault_path, master_password)?;
    let protected_password = protect_password(master_password, vault_path)?;
    let mut store = read_store(app)?;
    let key = normalize_path(vault_path);

    if let Some(entry) = store.entries.iter_mut().find(|entry| entry.vault_path == key) {
        entry.protected_password = protected_password;
    } else {
        store.entries.push(WindowsUnlockEntry {
            vault_path: key,
            protected_password,
        });
    }

    write_store(app, &store)
}

pub fn disable_windows_unlock(app: &AppHandle, vault_path: impl AsRef<Path>) -> VaultResult<()> {
    let vault_path = normalize_path(vault_path);
    let mut store = read_store(app)?;
    let before = store.entries.len();
    store.entries.retain(|entry| entry.vault_path != vault_path);
    if before != store.entries.len() {
        write_store(app, &store)?;
    }
    Ok(())
}

pub fn is_windows_unlock_enabled(app: &AppHandle, vault_path: impl AsRef<Path>) -> VaultResult<bool> {
    let vault_path = normalize_path(vault_path);
    let store = read_store(app)?;
    Ok(store.entries.iter().any(|entry| entry.vault_path == vault_path))
}

pub fn unlock_vault_with_windows(
    app: &AppHandle,
    vault_path: impl AsRef<Path>,
) -> VaultResult<crate::models::WindowsUnlockResult> {
    let vault_path = vault_path.as_ref();
    let store = read_store(app)?;
    let key = normalize_path(vault_path);
    let entry = store
        .entries
        .iter()
        .find(|entry| entry.vault_path == key)
        .ok_or_else(|| VaultError::Validation("No hay desbloqueo de Windows configurado para esta bóveda".to_string()))?;
    let password = unprotect_password(&entry.protected_password, vault_path)?;
    let vault = vault::unlock_vault(vault_path, &password)?;
    Ok(crate::models::WindowsUnlockResult {
        vault,
        master_password: password,
    })
}

fn read_store(app: &AppHandle) -> VaultResult<WindowsUnlockStore> {
    let path = store_path(app)?;
    if !path.exists() {
        return Ok(WindowsUnlockStore::default());
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_store(app: &AppHandle, store: &WindowsUnlockStore) -> VaultResult<()> {
    let path = store_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(store)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn store_path(app: &AppHandle) -> VaultResult<PathBuf> {
    app.path()
        .app_data_dir()
        .map(|path| path.join(WINDOWS_UNLOCK_FILE))
        .map_err(|error| VaultError::Validation(error.to_string()))
}

fn normalize_path(path: impl AsRef<Path>) -> String {
    path.as_ref().to_string_lossy().to_string().to_lowercase()
}

#[cfg(target_os = "windows")]
fn protect_password(master_password: &str, vault_path: &Path) -> VaultResult<String> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB},
    };

    let mut input_bytes = master_password.as_bytes().to_vec();
    let mut entropy_bytes = vault_path.to_string_lossy().as_bytes().to_vec();
    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: input_bytes.len() as u32,
        pbData: input_bytes.as_mut_ptr(),
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut input_blob,
            ptr::null(),
            &mut entropy_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output_blob,
        )
    };
    if ok == 0 {
        return Err(VaultError::Validation(
            "Windows no pudo proteger la contraseña para desbloqueo local".to_string(),
        ));
    }

    let protected = unsafe {
        std::slice::from_raw_parts(output_blob.pbData as *const u8, output_blob.cbData as usize)
            .to_vec()
    };
    unsafe {
        LocalFree(output_blob.pbData as *mut c_void);
    }
    Ok(STANDARD.encode(protected))
}

#[cfg(target_os = "windows")]
fn unprotect_password(protected_password: &str, vault_path: &Path) -> VaultResult<String> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB},
    };

    let mut protected_bytes = STANDARD
        .decode(protected_password)
        .map_err(|_| VaultError::Validation("Datos de desbloqueo de Windows inválidos".to_string()))?;
    let mut entropy_bytes = vault_path.to_string_lossy().as_bytes().to_vec();
    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: protected_bytes.len() as u32,
        pbData: protected_bytes.as_mut_ptr(),
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input_blob,
            ptr::null_mut(),
            &mut entropy_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut output_blob,
        )
    };
    if ok == 0 {
        return Err(VaultError::Validation(
            "Windows no pudo desbloquear esta bóveda. Inicia sesión con el usuario correcto".to_string(),
        ));
    }

    let plain = unsafe {
        std::slice::from_raw_parts(output_blob.pbData as *const u8, output_blob.cbData as usize)
            .to_vec()
    };
    unsafe {
        LocalFree(output_blob.pbData as *mut c_void);
    }
    String::from_utf8(plain)
        .map_err(|_| VaultError::Validation("La contraseña protegida no es válida".to_string()))
}

#[cfg(not(target_os = "windows"))]
fn protect_password(_master_password: &str, _vault_path: &Path) -> VaultResult<String> {
    Err(VaultError::Validation(
        "El desbloqueo de Windows solo está disponible en Windows".to_string(),
    ))
}

#[cfg(not(target_os = "windows"))]
fn unprotect_password(_protected_password: &str, _vault_path: &Path) -> VaultResult<String> {
    Err(VaultError::Validation(
        "El desbloqueo de Windows solo está disponible en Windows".to_string(),
    ))
}
