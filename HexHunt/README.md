# HexHunt Desktop

The main HexHunt desktop application: a React/Tauri interface backed by a Rust agent runtime for authorized, evidence-based web reconnaissance.

## Development

```bash
npm install
npm run desktop:dev
```

Create a production bundle with:

```bash
npm run desktop:build
```

Configure the OpenRouter credential through the application settings or the `OPENROUTER_API_KEY` environment variable. Never commit credentials or runtime databases.

See the repository-level README for capabilities, safety boundaries, and the public-release structure.
