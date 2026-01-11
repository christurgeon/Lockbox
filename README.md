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
lockbox encrypt document.pdf image.png nodes.md

# Force overwrite of existing .lb files
lockbox encrypt secret.txt --force
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