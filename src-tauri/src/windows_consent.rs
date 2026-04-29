use crate::error::{VaultError, VaultResult};

#[cfg(target_os = "windows")]
pub async fn verify_windows_user() -> VaultResult<()> {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
    };

    let availability_op = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|_| {
            VaultError::Validation(
                "No se pudo consultar Windows Hello en este dispositivo".to_string(),
            )
        })?;
    let availability = availability_op
        .get()
        .map_err(|_| {
            VaultError::Validation(
                "No se pudo consultar Windows Hello en este dispositivo".to_string(),
            )
        })?;

    match availability {
        UserConsentVerifierAvailability::Available => {}
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            return Err(VaultError::Validation(
                "Configura Windows Hello (PIN/huella/rostro) para usar este desbloqueo".to_string(),
            ));
        }
        UserConsentVerifierAvailability::DeviceNotPresent => {
            return Err(VaultError::Validation(
                "Este dispositivo no tiene soporte de Windows Hello".to_string(),
            ));
        }
        UserConsentVerifierAvailability::DisabledByPolicy => {
            return Err(VaultError::Validation(
                "Windows Hello está deshabilitado por políticas del sistema".to_string(),
            ));
        }
        UserConsentVerifierAvailability::DeviceBusy => {
            return Err(VaultError::Validation(
                "Windows Hello está ocupado. Intenta nuevamente".to_string(),
            ));
        }
        _ => {
            return Err(VaultError::Validation(
                "Windows Hello no está disponible en este momento".to_string(),
            ));
        }
    }

    let prompt = HSTRING::from("Verifica tu identidad para desbloquear SecretSafe");
    let verification_op = UserConsentVerifier::RequestVerificationAsync(&prompt)
        .map_err(|_| {
            VaultError::Validation(
                "No se pudo iniciar la verificación de Windows Hello".to_string(),
            )
        })?;
    let verification = verification_op
        .get()
        .map_err(|_| {
            VaultError::Validation(
                "No se pudo completar la verificación de Windows Hello".to_string(),
            )
        })?;

    match verification {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => {
            Err(VaultError::Validation("Verificación cancelada por el usuario".to_string()))
        }
        UserConsentVerificationResult::RetriesExhausted => Err(VaultError::Validation(
            "Se agotaron los intentos de verificación".to_string(),
        )),
        UserConsentVerificationResult::DeviceBusy => Err(VaultError::Validation(
            "Windows Hello está ocupado. Intenta nuevamente".to_string(),
        )),
        UserConsentVerificationResult::DisabledByPolicy => Err(VaultError::Validation(
            "Windows Hello está deshabilitado por políticas del sistema".to_string(),
        )),
        UserConsentVerificationResult::NotConfiguredForUser => Err(VaultError::Validation(
            "Configura Windows Hello (PIN/huella/rostro) para usar este desbloqueo".to_string(),
        )),
        _ => Err(VaultError::Validation(
            "No se pudo verificar la identidad con Windows Hello".to_string(),
        )),
    }
}

#[cfg(not(target_os = "windows"))]
pub async fn verify_windows_user() -> VaultResult<()> {
    Err(VaultError::Validation(
        "El desbloqueo de Windows solo está disponible en Windows".to_string(),
    ))
}
