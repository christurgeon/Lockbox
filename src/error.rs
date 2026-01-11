use thiserror::Error;

#[derive(Error, Debug)]
pub enum LockboxError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file extension: expected .lb for decryption")]
    InvalidExtension,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or corrupted file")]
    DecryptionFailed,

    #[error("Invalid file format: not a valid Lockbox encryptedfile")]
    InvalidFileFormat,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("Operation cancelled by user")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, LockboxError>;
