# Lockbox 🔐

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)

A secure file encryption CLI tool built in Rust. Lockbox uses industry-standard cryptographic primitives to protect your files with a password.

## Installation

### From Source

```bash
git clone https://github.com/christurgeon/lockbox.git
cd lockbox
cargo build --release
cp ./target/release/lockbox ~/.local/bin/
```

## Quick Start

```bash
# Encrypt a file (password prompt will appear)
lockbox encrypt secret.txt
# Creates: secret.lb

# Decrypt a file
lockbox decrypt secret.lb
# Restores: secret.txt
```

## Usage

### Encrypt Files

```bash
# Encrypt a single file
lockbox encrypt secret.txt

# Encrypt multiple files
lockbox encrypt document.pdf image.png notes.md

# Force overwrite of existing .lb files
lockbox encrypt secret.txt --force

# Securely delete originals after encryption (3-pass random overwrite)
lockbox encrypt secret.txt --shred

# Combine flags
lockbox encrypt secret.txt -f -s
```

You'll be prompted to enter and confirm your password (hidden input):

```
🔐 Lockbox Encryption

Enter password:
Confirm password:

Encrypting secret.txt ... ✓ → secret.lb
```

> **Note:** The original file extension is encrypted inside the `.lb` file and will be restored on decryption. This hides the file type from observers.

### Decrypt Files

```bash
# Decrypt a single file
lockbox decrypt secret.lb

# Decrypt to a specific directory
lockbox decrypt secret.lb --output ./decrypted/

# Decrypt multiple files
lockbox decrypt file1.lb file2.lb file3.lb -o ./output/

# Force overwrite of existing files
lockbox decrypt secret.lb --force
```

### Directory Encryption

Lockbox can recursively encrypt or decrypt entire directories, preserving the directory structure:

```bash
# Encrypt all files in a directory
lockbox encrypt ./my-folder/

# Decrypt all .lb files in a directory to an output location
lockbox decrypt ./my-folder/ -o ./decrypted/

# Encrypt a directory and securely delete the originals
lockbox encrypt ./sensitive-docs/ --shred
```

### Piping (Stdin/Stdout)

Lockbox supports reading from stdin and writing to stdout for composability with other tools. When no files are provided and stdin is piped, Lockbox operates in streaming mode:

```bash
# Encrypt from stdin to a file
cat secret.txt | lockbox encrypt > secret.lb

# Decrypt from stdin to a file
cat secret.lb | lockbox decrypt > secret.txt

# Chain with other tools
tar cf - ./docs/ | lockbox encrypt > docs.tar.lb
cat docs.tar.lb | lockbox decrypt | tar xf -
```

Password prompts are written to stderr, so they won't interfere with piped data.

### Command Aliases

For convenience, shorthand aliases are available:

| Command | Aliases |
|---------|---------|
| `encrypt` | `enc`, `e` |
| `decrypt` | `dec`, `d` |

```bash
lockbox e secret.txt        # same as: lockbox encrypt secret.txt
lockbox d secret.lb -o out/ # same as: lockbox decrypt secret.lb -o out/
```

### Flags Reference

#### Encrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing `.lb` files without prompting |
| `--shred` | `-s` | Securely delete originals after encryption (also `--delete`) |

#### Decrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing output files without prompting |
| `--output <DIR>` | `-o` | Output directory for decrypted files |

## Security

Lockbox uses the following cryptographic primitives:

- **Argon2id** for password-based key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- **ChaCha20-Poly1305** for authenticated encryption (256-bit keys, 96-bit nonces)
- **Secure memory handling** via `zeroize` (key material zeroed on drop) and `mlock` (prevents swap to disk on Unix)
- **Secure deletion** via `--shred` overwrites files with cryptographically random data (3 passes) before unlinking

KDF parameters are stored in the encrypted file header, allowing future upgrades without breaking existing files.

## Development

```bash
# Run tests
cargo test

# Run lints
cargo clippy

# Format code
cargo fmt

# Build release
cargo build --release
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
