# Contributing to Lockbox

Thank you for your interest in contributing to Lockbox! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/christurgeon/lockbox.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run lints: `cargo clippy && cargo fmt --check`
7. Commit your changes
8. Push and create a Pull Request

## Development Setup

### Prerequisites

- Rust 1.92 or later
- Cargo

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with verbose output
RUST_BACKTRACE=1 cargo run -- encrypt test.txt
```

### Code Style

- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings
- Write tests for new functionality
- Document public APIs with doc comments

## Pull Request Guidelines

1. **Keep PRs focused** - One feature or fix per PR
2. **Write clear commit messages** - Explain what and why
3. **Add tests** - For new features and bug fixes
4. **Update documentation** - If behavior changes

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, please email the maintainers directly or use GitHub's private security reporting feature.

### Security-Related Changes

For changes that affect cryptographic operations:

1. Explain the security implications
2. Reference relevant standards or best practices
3. Consider backward compatibility with existing encrypted files

## Questions?

Feel free to open an issue for questions or discussions about potential changes.
