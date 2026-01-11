mod cli;
mod crypto;
mod error;
mod file_ops;

use std::io::{self, Write};

use colored::Colorize;
use zeroize::Zeroizing;

use cli::{Cli, Commands};
use error::{LockboxError, Result};
use file_ops::{decrypt_file_to_path, encrypt_file};

/// Prompt for password input (hidden from terminal)
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let password = rpassword::read_password()
        .map_err(|e| LockboxError::IoError(io::Error::new(io::ErrorKind::Other, e)))?;

    Ok(Zeroizing::new(password))
}

/// Prompt for password with confirmation (for encryption)
fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
    }

    let confirm = prompt_password("Confirm password: ")?;

    if *password != *confirm {
        return Err(LockboxError::PasswordMismatch);
    }

    Ok(password)
}

/// Prompt for password (for decryption - no confirmation needed)
fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;

    if password.is_empty() {
        return Err(LockboxError::EmptyPassword);
    }

    Ok(password)
}

fn run() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Commands::Encrypt { files, force } => {
            println!("{}", "🔐 Lockbox Encryption".cyan().bold());
            println!();

            let password = prompt_password_with_confirm()?;
            println!();

            let mut success_count = 0;
            let mut error_count = 0;

            for file_path in &files {
                print!("Encrypting {} ... ", file_path.display());
                io::stdout().flush()?;

                match encrypt_file(file_path, password.as_bytes(), force) {
                    Ok(output_path) => {
                        println!("{} → {}", "✓".green(), output_path.display());
                        success_count += 1;
                    }
                    Err(LockboxError::Cancelled) => {
                        println!("{}", "skipped".yellow());
                    }
                    Err(e) => {
                        println!("{} {}", "✗".red(), e);
                        error_count += 1;
                    }
                }
            }

            println!();
            if error_count == 0 {
                println!(
                    "{} {} file(s) encrypted successfully",
                    "✓".green(),
                    success_count
                );
            } else {
                println!(
                    "{} {} succeeded, {} failed",
                    "⚠".yellow(),
                    success_count,
                    error_count
                );
            }
        }
        Commands::Decrypt {
            files,
            output,
            force,
        } => {
            println!("{}", "🔓 Lockbox Decryption".cyan().bold());
            println!();

            let password = prompt_password_decrypt()?;
            println!();

            let mut success_count = 0;
            let mut error_count = 0;

            for file_path in &files {
                print!("Decrypting {} ... ", file_path.display());
                io::stdout().flush()?;

                match decrypt_file_to_path(file_path, password.as_bytes(), output.as_deref(), force)
                {
                    Ok(output_path) => {
                        println!("{} → {}", "✓".green(), output_path.display());
                        success_count += 1;
                    }
                    Err(LockboxError::Cancelled) => {
                        println!("{}", "skipped".yellow());
                    }
                    Err(LockboxError::DecryptionFailed) => {
                        println!("{} incorrect password or corrupted file", "✗".red());
                        error_count += 1;
                    }
                    Err(e) => {
                        println!("{} {}", "✗".red(), e);
                        error_count += 1;
                    }
                }
            }

            println!();
            if error_count == 0 {
                println!(
                    "{} {} file(s) decrypted successfully",
                    "✓".green(),
                    success_count
                );
            } else {
                println!(
                    "{} {} succeeded, {} failed",
                    "⚠".yellow(),
                    success_count,
                    error_count
                );
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}
