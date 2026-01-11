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
    let encrypted = create_encrypted_file(password, &original_filename, &plaintext)?;

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
            // Uee current directory
            PathBuf::from(&original_filename)
        }
    };

    // Check if we should overwrite
    check_overwrite(&output_path, force)?;

    // Write decrypted file
    fs::write(&output_path, plaintext)?;

    Ok(output_path)
}
