# Contributing to AEGIS OS

Thank you for your interest in contributing to AEGIS OS!

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `cargo test --workspace`
5. Run clippy: `cargo clippy`
6. Commit: `git commit -m "Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Development Setup
```bash
git clone https://github.com/Moudaxx/aegis-os.git
cd aegis-os
cp .env.example .env  # Add your API keys
cargo build
cargo test --workspace
```

## Code Style

- Follow Rust standard formatting: `cargo fmt`
- No clippy warnings: `cargo clippy`
- All new features must include tests
- Security-related changes require Red Team test coverage

## Security

If you discover a security vulnerability, please report it privately.
See [SECURITY.md](SECURITY.md) for details.

## Areas for Contribution

- Additional AI backend integrations
- New Red Team attack tests
- MCP tool implementations
- Documentation improvements
- Performance optimizations
- Kubernetes deployment manifests