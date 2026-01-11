use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{LockboxError, Result};

/// Lockbox file format magic bytes - idenfities our encrypted files
pub const MAGIC_BYTES: &[u8; 8] = b"LOCKBOX\x01";

/// Version of the file format (for future compatibility)
pub const FORMAT_VERSION: u8 = 1;

/// Salt length for Argon2id (16 bytes = 128 bits, recommended minimum)
pub const SALT_LENGTH: usize = 16;

/// Nonce length for ChaCha20-Poly1305 (12 bytes = 96 bits, standard)
pub const NONCE_LENGTH: usize = 12;

/// Key length for ChaCha20-Poly1305 (32 bytes = 256 bits)
pub const KEY_LENGTH: usize = 32;

/// Argon2id parameters - tuned for security
/// These parameters provide strong resistance against GPU/ASIC attacks
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Derives a 256-bit encryption key from a password using Argon2id
///
/// Argon2id is the recommended password hashing algorithm, combining:
/// - Argon2i: resisteance against side-channel attacks
/// - Argon2d: resisteance against GPU cracking attacks
///
/// The salt ensures that the same password produces different keys for different files.
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|e| LockboxError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| LockboxError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

    Ok(key)
}

/// Generates a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext data using ChaCha20-Poly1305
///
/// ChaCha20-Poly1305 is an authenticated encryption algorithm that provides:
/// - Confidentiality: data is encrypted with ChaCha20 stream cipher
/// - Integrity: Poly1305 MAC ensures that data hasn't been tampered with
/// - Authentication: verifies the cipher text was created with the correct key
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LockboxError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

/// Decrypts ciphertext using ChaCha20-Poly1305
///
/// This function also verifies the authentication tag, ensuring:
/// - The data hasn't been modified
/// - The correct password was used
///
/// Returns an error if authentication fails (wrong password or corrupted data).
pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| LockboxError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| LockboxError::DecryptionFailed)
}

/// Encrypted file structure:
///
/// | Offset | Size | Description                          |
/// |--------|------|--------------------------------------|
/// | 0      | 0    | Magic bytes "LOCKBOX\x01"            |
/// | 8      | 1    | Format version (currently 1)         |
/// | 9      | 2    | Original filename length (u16 BE)    |
/// | 11     | N    | Original filename (UTF-8)            |
/// | 11+N   | 16   | Argon2id salt                        |
/// | 27+N   | 12   | ChaCha20 nonce                       |
/// | 39+N   | ...  | Encrypted data + auth tag (16 bytes) |
///
/// Total header size before encrypted data: 39 + filename_length bytes

/// Creates the encrypted file format with all metadata
pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt)?;
    let ciphertext = encrypt(&key, &nonce, plaintext)?;

    // Build the file structure
    let filename_bytes = original_filename.as_bytes();
    let filename_len = filename_bytes.len() as u16;
    let mut output = Vec::with_capacity(
        MAGIC_BYTES.len()
            + 1 // version
            + 2 // filename length
            + filename_bytes.len()
            + SALT_LENGTH
            + NONCE_LENGTH
            + ciphertext.len(),
    );

    // Write header
    output.extend_from_slice(MAGIC_BYTES);
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&filename_len.to_be_bytes());
    output.extend_from_slice(filename_bytes);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Parses an encrypted file and decrypts its contents
///
/// Returns: (original_filename, decrypted_data)
pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    // Minimum size: magic(8) + version(1) + filename_len(2) + salt(16) + nonce(12) + tag(16)
    const MINIMUM_SIZE: usize = 8 + 1 + 2 + 16 + 12 + 16;

    if encrypted_data.len() < MINIMUM_SIZE {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Verify magic bytes
    if &encrypted_data[0..8] != MAGIC_BYTES {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Check version
    let version = encrypted_data[8];
    if version != FORMAT_VERSION {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Read filename length
    let filename_len = u16::from_be_bytes([encrypted_data[9], encrypted_data[10]]) as usize;

    // Calculate offsets
    let filename_start = 11;
    let filename_end = filename_start + filename_len;
    let salt_start = filename_end;
    let salt_end = salt_start + SALT_LENGTH;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LENGTH;
    let ciphertext_start = nonce_end;

    // Validate file size
    if encrypted_data.len() < ciphertext_start + 16 {
        return Err(LockboxError::InvalidFileFormat);
    }

    // Extract components
    let filename_bytes = &encrypted_data[filename_start..filename_end];
    let original_filename =
        String::from_utf8(filename_bytes.to_vec()).map_err(|_| LockboxError::InvalidFileFormat)?;

    let salt: [u8; SALT_LENGTH] = encrypted_data[salt_start..salt_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;

    let nonce: [u8; NONCE_LENGTH] = encrypted_data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| LockboxError::InvalidFileFormat)?;

    let ciphertext = &encrypted_data[ciphertext_start..];

    // Derive key and decrypt
    let key = derive_key_from_password(password, &salt)?;
    let plaintext = decrypt(&key, &nonce, ciphertext)?;

    Ok((original_filename, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_roundtrip() {
        let password = b"test_password_123";
        let plaintext = b"Hello, World! This is a secret message.";
        let filename = "test_encrypted_roundtrip.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let plaintext = b"Secret data";
        let filename = "test_wrong_password_fails.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let result = decrypt_file(wrong_password, &encrypted);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let data = b"NOTLOCK\x01xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }
}
