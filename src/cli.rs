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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // ==================== Basic Parsing Tests ====================

    #[test]
    fn test_cli_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_encrypt_single_file() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.txt"));
                assert!(!force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_multiple_files() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "a.txt", "b.pdf", "c.doc"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force } => {
                assert_eq!(files.len(), 3);
                assert_eq!(files[0], PathBuf::from("a.txt"));
                assert_eq!(files[1], PathBuf::from("b.pdf"));
                assert_eq!(files[2], PathBuf::from("c.doc"));
                assert!(!force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_short() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "-f", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force } => {
                assert_eq!(files.len(), 1);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_long() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "--force", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { force, .. } => {
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_single_file() {
        let cli = Cli::try_parse_from(["lockbox", "decrypt", "file.lb"]).unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.lb"));
                assert!(output.is_none());
                assert!(!force);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_short() {
        let cli =
            Cli::try_parse_from(["lockbox", "decrypt", "file.lb", "-o", "./output/"]).unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("./output/")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_long() {
        let cli =
            Cli::try_parse_from(["lockbox", "decrypt", "file.lb", "--output", "/tmp/out"]).unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("/tmp/out")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_force_and_output() {
        let cli = Cli::try_parse_from([
            "lockbox", "decrypt", "a.lb", "b.lb", "-o", "./out", "--force",
        ])
        .unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
            } => {
                assert_eq!(files.len(), 2);
                assert_eq!(output, Some(PathBuf::from("./out")));
                assert!(force);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Alias Tests ====================

    #[test]
    fn test_encrypt_alias_enc() {
        let cli = Cli::try_parse_from(["lockbox", "enc", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_alias_e() {
        let cli = Cli::try_parse_from(["lockbox", "e", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_dec() {
        let cli = Cli::try_parse_from(["lockbox", "dec", "file.lb"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.lb"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_d() {
        let cli = Cli::try_parse_from(["lockbox", "d", "file.lb"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.lb"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Error Cases ====================

    #[test]
    fn test_encrypt_requires_file() {
        let result = Cli::try_parse_from(["lockbox", "encrypt"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_requires_file() {
        let result = Cli::try_parse_from(["lockbox", "decrypt"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_command_fails() {
        let result = Cli::try_parse_from(["lockbox", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_command_fails() {
        let result = Cli::try_parse_from(["lockbox"]);
        assert!(result.is_err());
    }

    // ==================== Path Handling Tests ====================

    #[test]
    fn test_absolute_path() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "/home/user/secret.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("/home/user/secret.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_relative_path_with_dots() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "../parent/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("../parent/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_path_with_spaces() {
        let cli = Cli::try_parse_from(["lockbox", "encrypt", "path with spaces/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("path with spaces/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_mixed_flags_and_files() {
        // Force flag before files
        let cli1 = Cli::try_parse_from(["lockbox", "encrypt", "-f", "a.txt", "b.txt"]).unwrap();
        match cli1.command {
            Commands::Encrypt { files, force } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }

        // Force flag after files
        let cli2 = Cli::try_parse_from(["lockbox", "encrypt", "a.txt", "b.txt", "-f"]).unwrap();
        match cli2.command {
            Commands::Encrypt { files, force } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }
}
