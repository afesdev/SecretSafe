use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("No se pudo leer o escribir la bóveda: {0}")]
    Io(#[from] std::io::Error),

    #[error("El archivo de bóveda no tiene un formato válido: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("La contraseña maestra no desbloquea esta bóveda")]
    InvalidPassword,

    #[error("No se pudo completar la operación criptográfica")]
    Crypto,

    #[error("{0}")]
    Validation(String),

    #[error("Versión de bóveda no soportada: {0}")]
    UnsupportedVersion(u16),
}

pub type VaultResult<T> = Result<T, VaultError>;
