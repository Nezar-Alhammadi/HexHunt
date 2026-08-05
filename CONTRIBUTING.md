# Contributing to HexHunt

Thank you for helping improve authorized, evidence-driven security research.

## Before you begin

- Use only targets you own or have explicit permission to test.
- Never submit API keys, cookies, tokens, private target data, or undisclosed vulnerability details.
- Search existing issues before opening a new one.
- For security-sensitive reports, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

HexHunt requires Node.js 20+, Rust stable, and the Linux dependencies required by Tauri/WebKitGTK.

```bash
cd HexHunt
npm install
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
```

For the benchmark:

```bash
cd HexHunt-Bench
npm install
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
```

## Pull requests

1. Keep the change focused and explain the user-visible outcome.
2. Add or update tests for behavior changes.
3. Run the relevant frontend build and Rust tests.
4. Describe security and scope implications explicitly.
5. Do not weaken scope checks, evidence requirements, or secret redaction to make a test pass.

Issues labeled `good first issue` are intentionally small starting points. Ask questions on the issue before doing large work so efforts do not overlap.

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
