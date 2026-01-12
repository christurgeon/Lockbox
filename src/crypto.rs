use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{LockboxError, Result};

/// Lockbox file format magic bytes - indentifies our encrypted files
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
/// - Argon2i: resistance against side-channel attacks
/// - Argon2d: resistance against GPU cracking attacks
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

// Encrypted file structure:
//
// | Offset | Size | Description                          |
// |--------|------|--------------------------------------|
// | 0      | 0    | Magic bytes "LOCKBOX\x01"            |
// | 8      | 1    | Format version (currently 1)         |
// | 9      | 2    | Original filename length (u16 BE)    |
// | 11     | N    | Original filename (UTF-8)            |
// | 11+N   | 16   | Argon2id salt                        |
// | 27+N   | 12   | ChaCha20 nonce                       |
// | 39+N   | ...  | Encrypted data + auth tag (16 bytes) |
//
// Total header size before encrypted data: 39 + filename_length bytes

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

    // ==================== Key Derivation Tests ====================

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();

        assert_eq!(
            *key1, *key2,
            "Same password and salt should produce same key"
        );
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"test_password";
        let salt1 = [0u8; SALT_LENGTH];
        let salt2 = [1u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt1).unwrap();
        let key2 = derive_key_from_password(password, &salt2).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different salts should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0u8; SALT_LENGTH];
        let key1 = derive_key_from_password(b"password1", &salt).unwrap();
        let key2 = derive_key_from_password(b"password2", &salt).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different passwords should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_empty_password() {
        let salt = [0u8; SALT_LENGTH];
        let result = derive_key_from_password(b"", &salt);
        assert!(result.is_ok(), "Empty password should still derive a key");
    }

    #[test]
    fn test_derive_key_length() {
        let password = b"test";
        let salt = [0u8; SALT_LENGTH];
        let key = derive_key_from_password(password, &salt).unwrap();

        assert_eq!(
            key.len(),
            KEY_LENGTH,
            "Key should be exactly KEY_LENGTH bytes"
        );
    }

    // ==================== Salt & Nonce Generation Tests ====================

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_LENGTH);
    }

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2, "Generated salts should be unique");
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }

    #[test]
    fn test_generate_nonce_randomness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2, "Generated nonces should be unique");
    }

    // ==================== Low-Level Encrypt/Decrypt Tests ====================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext1 = encrypt(&key, &nonce1, plaintext).unwrap();
        let ciphertext2 = encrypt(&key, &nonce2, plaintext).unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Different nonces should produce different ciphertext"
        );
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [0u8; KEY_LENGTH];
        let key2 = [1u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key1, &nonce, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce1, plaintext).unwrap();
        let result = decrypt(&key, &nonce2, &ciphertext);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_auth_tag() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();

        // ChaCha20-Poly1305 adds a 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let truncated = &ciphertext[..ciphertext.len() - 1];

        let result = decrypt(&key, &nonce, truncated);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    // ==================== File Format Tests ====================

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

    #[test]
    fn test_file_too_small() {
        let data = b"LOCKBOX";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }

    #[test]
    fn test_invalid_version() {
        // Create valid header but with wrong version
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_BYTES);
        data.push(99); // Invalid version
        data.extend_from_slice(&[0u8; 50]); // Padding

        let result = decrypt_file(b"password", &data);
        assert!(matches!(result, Err(LockboxError::InvalidFileFormat)));
    }

    #[test]
    fn test_empty_file_encryption() {
        let password = b"password";
        let plaintext = b"";
        let filename = "empty.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_unicode_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "文件名_тест_🔐.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_long_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "a".repeat(255);

        let encrypted = create_encrypted_file(password, &filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_file_with_spaces_in_name() {
        let password = b"password";
        let plaintext = b"content";
        let filename = "my secret file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_binary_data_encryption() {
        let password = b"password";
        // Binary data with all byte values
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let filename = "binary.bin";

        let encrypted = create_encrypted_file(password, filename, &plaintext).unwrap();
        let (_, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_encrypted_file_structure() {
        let password = b"password";
        let plaintext = b"test";
        let filename = "test.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Verify magic bytes
        assert_eq!(&encrypted[0..8], MAGIC_BYTES);

        // Verify version
        assert_eq!(encrypted[8], FORMAT_VERSION);

        // Verify filename length (big-endian u16)
        let filename_len = u16::from_be_bytes([encrypted[9], encrypted[10]]) as usize;
        assert_eq!(filename_len, filename.len());

        // Verify filename
        let stored_filename = std::str::from_utf8(&encrypted[11..11 + filename_len]).unwrap();
        assert_eq!(stored_filename, filename);
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let password = b"password";
        let plaintext = b"same data";
        let filename = "file.txt";

        let encrypted1 = create_encrypted_file(password, filename, plaintext).unwrap();
        let encrypted2 = create_encrypted_file(password, filename, plaintext).unwrap();

        // Due to random salt and nonce, outputs should differ
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_corrupted_salt_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the salt area (after magic + version + filename_len + filename)
        let salt_offset = 11 + filename.len();
        encrypted[salt_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_corrupted_nonce_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the nonce area
        let nonce_offset = 11 + filename.len() + SALT_LENGTH;
        encrypted[nonce_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_special_characters_in_password() {
        let password = "pässwörd🔐!@#$%^&*()".as_bytes();
        let plaintext = b"secret";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_very_long_password() {
        let password = vec![b'a'; 10000];
        let plaintext = b"data";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(&password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(&password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }
}
