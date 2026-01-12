use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{create_encrypted_file, decrypt_file};
use crate::error::{LockboxError, Result};

/// The extension for encrypted lockbox files
pub const LOCKBOX_EXTENSION: &str = "lb";

/// Prompts the user for confirmation
pub fn prompt_confirmation(message: &str) -> Result<bool> {
    print!("{} [y/N]: ", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

/// Checks if the output file exists and prompts for confirmation if needed
pub fn check_overwrite(path: &Path, force: bool) -> Result<()> {
    if path.exists() {
        if force {
            return Ok(());
        }

        let prompt = format!("File '{}' already exists. Overwrite?", path.display());

        if prompt_confirmation(&prompt)? {
            Ok(())
        } else {
            Err(LockboxError::Cancelled)
        }
    } else {
        Ok(())
    }
}

/// Encrypts a single file
///
/// - Reads the source file
/// - Encrypts it with the provided password
/// - Writes to `<stem>.lb` (original extension is encrypted inside)
/// - Preserves the original file
pub fn encrypt_file(source_path: &Path, password: &[u8], force: bool) -> Result<PathBuf> {
    // Verify source exists
    if !source_path.exists() {
        return Err(LockboxError::FileNotFound(
            source_path.display().to_string(),
        ));
    }

    // Get the original filename (just the filename, not the full path)
    // This includes the extension and will be stored encrypted
    let original_filename = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            LockboxError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid filename",
            ))
        })?;

    // Get the file stem (name without extension)
    let file_stem = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            LockboxError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid filename",
            ))
        })?
        .to_string();

    // Create the output path: same directory, stem + lb
    // e.g., "secret.txt" -> "secret.lb", "document.pdf" -> "document.lb"
    let output_path = source_path
        .parent()
        .map(|p| p.join(format!("{}.{}", file_stem, LOCKBOX_EXTENSION)))
        .unwrap_or_else(|| PathBuf::from(format!("{}.{}", file_stem, LOCKBOX_EXTENSION)));

    // Check if we should overwrite
    check_overwrite(&output_path, force)?;

    // Read source file
    let plaintext = fs::read(source_path)?;

    // Encrypt
    let encrypted = create_encrypted_file(password, original_filename, &plaintext)?;

    // Write encrypted file
    fs::write(&output_path, encrypted)?;

    Ok(output_path)
}

/// Decrypts a single .lb file
///
/// - Reads the encrypted file
/// - Decrypts it with the provided password
/// - Writes to the output directory with the original filename
pub fn decrypt_file_to_path(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
) -> Result<PathBuf> {
    // Verify source exists
    if !source_path.exists() {
        return Err(LockboxError::FileNotFound(
            source_path.display().to_string(),
        ));
    }

    // Verify it has .lb extension
    let extension = source_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if extension != LOCKBOX_EXTENSION {
        return Err(LockboxError::InvalidExtension);
    }

    // Read encrypted file
    let encrypted_data = fs::read(source_path)?;

    // Decrypt
    let (original_filename, plaintext) = decrypt_file(password, &encrypted_data)?;

    // Determine output path
    let output_path = match output_dir {
        Some(dir) => {
            // Ensure directory exists
            if !dir.exists() {
                fs::create_dir_all(dir)?;
            }
            dir.join(&original_filename)
        }
        None => {
            // Use current directory
            PathBuf::from(&original_filename)
        }
    };

    // Check if we should overwrite
    check_overwrite(&output_path, force)?;

    // Write decrypted file
    fs::write(&output_path, plaintext)?;

    Ok(output_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_temp_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    // ==================== encrypt_file Tests ====================

    #[test]
    fn test_encrypt_file_creates_lb_file() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "secret.txt", b"my secret data");

        let result = encrypt_file(&source, b"password", true).unwrap();

        assert_eq!(result, temp_dir.path().join("secret.lb"));
        assert!(result.exists());
    }

    #[test]
    fn test_encrypt_file_preserves_original() {
        let temp_dir = TempDir::new().unwrap();
        let content = b"original content";
        let source = create_temp_file(&temp_dir, "file.txt", content);

        encrypt_file(&source, b"password", true).unwrap();

        // Original file should still exist with same content
        assert!(source.exists());
        assert_eq!(fs::read(&source).unwrap(), content);
    }

    #[test]
    fn test_encrypt_file_nonexistent_fails() {
        let result = encrypt_file(Path::new("/nonexistent/file.txt"), b"password", true);
        assert!(matches!(result, Err(LockboxError::FileNotFound(_))));
    }

    #[test]
    fn test_encrypt_file_different_extensions() {
        let temp_dir = TempDir::new().unwrap();

        // Test .pdf
        let pdf = create_temp_file(&temp_dir, "doc.pdf", b"pdf content");
        let result = encrypt_file(&pdf, b"pass", true).unwrap();
        assert_eq!(result.file_name().unwrap(), "doc.lb");

        // Test .tar.gz (only last extension is removed)
        let targz = create_temp_file(&temp_dir, "archive.tar.gz", b"archive");
        let result = encrypt_file(&targz, b"pass", true).unwrap();
        assert_eq!(result.file_name().unwrap(), "archive.tar.lb");

        // Test no extension
        let noext = create_temp_file(&temp_dir, "noextension", b"data");
        let result = encrypt_file(&noext, b"pass", true).unwrap();
        assert_eq!(result.file_name().unwrap(), "noextension.lb");
    }

    #[test]
    fn test_encrypt_file_output_is_valid_lockbox_format() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "test.txt", b"test data");

        let encrypted_path = encrypt_file(&source, b"password", true).unwrap();
        let encrypted_data = fs::read(&encrypted_path).unwrap();

        // Should start with magic bytes
        assert_eq!(&encrypted_data[0..8], b"LOCKBOX\x01");
    }

    #[test]
    fn test_encrypt_file_with_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let source = subdir.join("file.txt");
        fs::write(&source, b"data").unwrap();

        let result = encrypt_file(&source, b"pass", true).unwrap();
        assert_eq!(result, subdir.join("file.lb"));
    }

    // ==================== decrypt_file_to_path Tests ====================

    #[test]
    fn test_decrypt_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let original_content = b"super secret data 12345";
        let source = create_temp_file(&temp_dir, "original.txt", original_content);

        // Encrypt
        let encrypted_path = encrypt_file(&source, b"mypassword", true).unwrap();

        // Decrypt to different directory
        let output_dir = temp_dir.path().join("output");
        let decrypted_path =
            decrypt_file_to_path(&encrypted_path, b"mypassword", Some(&output_dir), true).unwrap();

        // Verify
        assert_eq!(decrypted_path.file_name().unwrap(), "original.txt");
        assert_eq!(fs::read(&decrypted_path).unwrap(), original_content);
    }

    #[test]
    fn test_decrypt_file_wrong_extension_fails() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "file.txt", b"not encrypted");

        let result = decrypt_file_to_path(&source, b"password", None, true);
        assert!(matches!(result, Err(LockboxError::InvalidExtension)));
    }

    #[test]
    fn test_decrypt_file_nonexistent_fails() {
        let result =
            decrypt_file_to_path(Path::new("/nonexistent/file.lb"), b"password", None, true);
        assert!(matches!(result, Err(LockboxError::FileNotFound(_))));
    }

    #[test]
    fn test_decrypt_file_wrong_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "secret.txt", b"data");

        let encrypted_path = encrypt_file(&source, b"correct_password", true).unwrap();
        let result = decrypt_file_to_path(&encrypted_path, b"wrong_password", None, true);

        assert!(matches!(result, Err(LockboxError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_file_creates_output_directory() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "file.txt", b"data");
        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();

        let nested_output = temp_dir.path().join("a").join("b").join("c");
        assert!(!nested_output.exists());

        decrypt_file_to_path(&encrypted_path, b"pass", Some(&nested_output), true).unwrap();

        assert!(nested_output.exists());
    }

    #[test]
    fn test_decrypt_file_to_current_directory() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "myfile.txt", b"content");
        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();

        // Change to temp directory for this test
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();

        // Decrypt without specifying output directory
        let decrypted = decrypt_file_to_path(&encrypted_path, b"pass", None, true).unwrap();

        // Restore original directory
        std::env::set_current_dir(original_dir).unwrap();

        assert_eq!(decrypted.file_name().unwrap(), "myfile.txt");
    }

    #[test]
    fn test_decrypt_corrupted_file_fails() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "file.txt", b"data");
        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();

        // Corrupt the encrypted file
        let mut encrypted_data = fs::read(&encrypted_path).unwrap();
        encrypted_data[20] ^= 0xFF;
        fs::write(&encrypted_path, encrypted_data).unwrap();

        let result = decrypt_file_to_path(&encrypted_path, b"pass", None, true);
        assert!(result.is_err());
    }

    // ==================== check_overwrite Tests ====================

    #[test]
    fn test_check_overwrite_nonexistent_file_ok() {
        let result = check_overwrite(Path::new("/definitely/does/not/exist.txt"), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_overwrite_force_existing_file_ok() {
        let temp_dir = TempDir::new().unwrap();
        let file = create_temp_file(&temp_dir, "exists.txt", b"content");

        let result = check_overwrite(&file, true);
        assert!(result.is_ok());
    }

    // ==================== Integration Tests ====================

    #[test]
    fn test_full_encrypt_decrypt_cycle_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let password = b"shared_password";

        // Create multiple files with different content
        let files = vec![
            ("doc1.txt", b"Document one content".as_slice()),
            ("doc2.pdf", b"PDF binary data here".as_slice()),
            (
                "image.png",
                &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            ),
        ];

        for (name, content) in &files {
            let source = create_temp_file(&temp_dir, name, content);
            let encrypted = encrypt_file(&source, password, true).unwrap();

            let output_dir = temp_dir.path().join("decrypted");
            let decrypted =
                decrypt_file_to_path(&encrypted, password, Some(&output_dir), true).unwrap();

            assert_eq!(decrypted.file_name().unwrap().to_str().unwrap(), *name);
            assert_eq!(fs::read(&decrypted).unwrap(), *content);
        }
    }

    #[test]
    fn test_encrypt_large_file() {
        let temp_dir = TempDir::new().unwrap();
        let large_content = vec![0xABu8; 5 * 1024 * 1024]; // 5 MB
        let source = create_temp_file(&temp_dir, "large.bin", &large_content);

        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();
        let output_dir = temp_dir.path().join("out");
        let decrypted_path =
            decrypt_file_to_path(&encrypted_path, b"pass", Some(&output_dir), true).unwrap();

        assert_eq!(fs::read(&decrypted_path).unwrap(), large_content);
    }

    #[test]
    fn test_encrypt_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "empty.txt", b"");

        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();
        let output_dir = temp_dir.path().join("out");
        let decrypted_path =
            decrypt_file_to_path(&encrypted_path, b"pass", Some(&output_dir), true).unwrap();

        assert_eq!(fs::read(&decrypted_path).unwrap(), b"");
    }

    #[test]
    fn test_filename_with_special_characters() {
        let temp_dir = TempDir::new().unwrap();
        let source = create_temp_file(&temp_dir, "file with spaces (1).txt", b"content");

        let encrypted_path = encrypt_file(&source, b"pass", true).unwrap();
        let output_dir = temp_dir.path().join("out");
        let decrypted_path =
            decrypt_file_to_path(&encrypted_path, b"pass", Some(&output_dir), true).unwrap();

        assert_eq!(
            decrypted_path.file_name().unwrap(),
            "file with spaces (1).txt"
        );
    }
}
