use chacha20poly1305::aead::rand_core::{OsRng, RngCore};

use crate::{
    error::{VaultError, VaultResult},
    models::{GeneratedPassword, PasswordGenerationOptions},
};

const UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub fn generate_password(
    options: Option<PasswordGenerationOptions>,
) -> VaultResult<GeneratedPassword> {
    let options = options.unwrap_or_default();
    validate_options(&options)?;

    let mut alphabet = Vec::new();
    let mut required_sets: Vec<&[u8]> = Vec::new();

    if options.include_uppercase {
        alphabet.extend_from_slice(UPPERCASE);
        required_sets.push(UPPERCASE);
    }

    if options.include_lowercase {
        alphabet.extend_from_slice(LOWERCASE);
        required_sets.push(LOWERCASE);
    }

    if options.include_numbers {
        alphabet.extend_from_slice(NUMBERS);
        required_sets.push(NUMBERS);
    }

    if options.include_symbols {
        alphabet.extend_from_slice(SYMBOLS);
        required_sets.push(SYMBOLS);
    }

    if alphabet.is_empty() {
        return Err(VaultError::Validation(
            "Activa al menos un tipo de carácter para generar la contraseña".to_string(),
        ));
    }

    let mut password = Vec::with_capacity(options.length);

    for set in required_sets {
        password.push(random_char(set));
    }

    while password.len() < options.length {
        password.push(random_char(&alphabet));
    }

    shuffle(&mut password);

    Ok(GeneratedPassword {
        password: String::from_utf8(password).map_err(|_| VaultError::Crypto)?,
    })
}

fn validate_options(options: &PasswordGenerationOptions) -> VaultResult<()> {
    if !(12..=128).contains(&options.length) {
        return Err(VaultError::Validation(
            "La contraseña generada debe tener entre 12 y 128 caracteres".to_string(),
        ));
    }

    let enabled_sets = [
        options.include_uppercase,
        options.include_lowercase,
        options.include_numbers,
        options.include_symbols,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();

    if options.length < enabled_sets {
        return Err(VaultError::Validation(
            "La longitud no alcanza para incluir todos los tipos seleccionados".to_string(),
        ));
    }

    Ok(())
}

fn random_char(alphabet: &[u8]) -> u8 {
    let index = (OsRng.next_u32() as usize) % alphabet.len();
    alphabet[index]
}

fn shuffle(bytes: &mut [u8]) {
    for index in (1..bytes.len()).rev() {
        let swap_index = (OsRng.next_u32() as usize) % (index + 1);
        bytes.swap(index, swap_index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_respects_requested_length() {
        let generated = generate_password(Some(PasswordGenerationOptions {
            length: 32,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }))
        .expect("password should be generated");

        assert_eq!(generated.password.len(), 32);
    }

    #[test]
    fn generated_password_rejects_short_lengths() {
        let result = generate_password(Some(PasswordGenerationOptions {
            length: 8,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }));

        assert!(matches!(result, Err(VaultError::Validation(_))));
    }
}
