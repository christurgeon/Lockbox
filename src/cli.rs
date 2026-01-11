use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Lockbox - A secure file encryption tool
///
/// Encrypts files using Argon2id for key derivation and ChaCha20-Poly1305 for
/// authenticated encryption. Your files are protected with military-grade security.
#[derive(Parser, Debug)]
#[command(name = "lockbox")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt one or more files
    ///
    /// Fields will be encrypted and saved with the .lb extension.
    /// Original files are preserved (not deleted).
    #[command(visible_alias = "enc", visible_alias = "e")]
    Encrypt {
        /// Files to encrypt
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Decrypt one or more .lb files
    ///
    /// Files will be decrypted and restored to their original format.
    #[command(visible_alias = "dec", visible_alias = "d")]
    Decrypt {
        /// Files to decrypt (must have .lb extension)
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,

        /// Output directory for decrypted files (defaults to current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
