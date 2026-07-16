# Contributing

Contributions are welcome. Keep pull requests focused and include tests for transfer-format or catalogue changes.

Before submitting:

```bash
npm run build
npm test
cargo fmt --manifest-path src-tauri/Cargo.toml -- --check
cargo test --manifest-path src-tauri/Cargo.toml
```

Live Telegram tests must use accounts intended for development, must respect all returned wait periods, and must never commit API credentials or session files.
