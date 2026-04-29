use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

use crate::{
    error::{VaultError, VaultResult},
    models::{CipherParams, KdfParams},
};

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;

const KDF_ALGORITHM: &str = "argon2id";
const CIPHER_ALGORITHM: &str = "xchacha20poly1305";

// Conservative defaults for desktop use. We can tune these after measuring unlock time.
const MEMORY_COST_KIB: u32 = 64 * 1024;
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 1;

pub fn default_kdf_params() -> KdfParams {
    KdfParams {
        algorithm: KDF_ALGORITHM.to_string(),
        memory_cost_kib: MEMORY_COST_KIB,
        time_cost: TIME_COST,
        parallelism: PARALLELISM,
        salt: random_bytes(SALT_LEN),
    }
}

pub fn encrypt_payload(
    master_password: &str,
    kdf: &KdfParams,
    plaintext: &[u8],
) -> VaultResult<(CipherParams, Vec<u8>)> {
    let nonce = random_bytes(NONCE_LEN);
    let cipher = cipher_from_password(master_password, kdf)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| VaultError::Crypto)?;

    Ok((
        CipherParams {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce,
        },
        ciphertext,
    ))
}

pub fn decrypt_payload(
    master_password: &str,
    kdf: &KdfParams,
    cipher_params: &CipherParams,
    ciphertext: &[u8],
) -> VaultResult<Vec<u8>> {
    if cipher_params.algorithm != CIPHER_ALGORITHM {
        return Err(VaultError::Crypto);
    }

    if cipher_params.nonce.len() != NONCE_LEN {
        return Err(VaultError::Crypto);
    }

    let cipher = cipher_from_password(master_password, kdf)?;
    cipher
        .decrypt(XNonce::from_slice(&cipher_params.nonce), ciphertext)
        .map_err(|_| VaultError::InvalidPassword)
}

fn cipher_from_password(master_password: &str, kdf: &KdfParams) -> VaultResult<XChaCha20Poly1305> {
    if kdf.algorithm != KDF_ALGORITHM {
        return Err(VaultError::Crypto);
    }

    if kdf.salt.len() != SALT_LEN {
        return Err(VaultError::Crypto);
    }

    let mut key = derive_key(master_password, kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| VaultError::Crypto)?;
    key.zeroize();

    Ok(cipher)
}

fn derive_key(master_password: &str, kdf: &KdfParams) -> VaultResult<[u8; KEY_LEN]> {
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::Crypto)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];

    argon2
        .hash_password_into(master_password.as_bytes(), &kdf.salt, &mut key)
        .map_err(|_| VaultError::Crypto)?;

    Ok(key)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
