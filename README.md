# HexHunt

HexHunt is an experimental, agentic reconnaissance platform for authorized web-security research. It combines a Rust core, a Tauri/React desktop interface, evidence-backed run records, scope enforcement, and a separate evaluation application.

> Use HexHunt only on systems you own or have explicit permission to test.

## Repository structure

| Directory | Purpose |
| --- | --- |
| `HexHunt/` | The desktop agent, Rust runtime, recon tools, evidence system, and run interface. |
| `HexHunt-Bench/` | An independent benchmark that runs HexHunt against owned local fixtures and scores persisted results. |

The public benchmark contains 12 public Gold cases with five deterministic variants each. Private transfer cases and their ground truth are intentionally not included.

## Current capabilities

- Authorized target and scope configuration.
- Agent-driven HTTP, JavaScript, API, DNS, historical, browser, and visual reconnaissance.
- Asset Graph, hypotheses, evidence, tool results, evaluation, and SQLite-backed run history.
- OpenRouter model integration with structured actions and local credential storage.
- A separate Recon Bench with ground-truth recall, evidence, precision, action-validity, stopping, efficiency, and safety metrics.

HexHunt is under active development. Benchmark scores are engineering signals, not proof that the system is ready for unsupervised real-world security testing.

## Requirements

- Node.js 20 or newer.
- Rust stable toolchain.
- Linux packages required by Tauri/WebKitGTK.
- An OpenRouter API key configured through HexHunt or `OPENROUTER_API_KEY`.

Never commit API keys or place them in task descriptions, run evidence, screenshots, or issue reports.

## Run HexHunt

```bash
cd HexHunt
npm install
npm run desktop:dev
```

## Run HexHunt Bench

Build HexHunt first so Cargo can resolve the sibling core dependency, then:

```bash
cd HexHunt-Bench
npm install
npm run desktop:dev
```

Each Bench run can invoke a paid model through OpenRouter. Runs begin only after the user selects a case and presses **Run case**.

## Public-release boundaries

- No API keys, local databases, run histories, build artifacts, or private reports are included.
- Sealed benchmark transfer cases remain private to preserve evaluation integrity.
- The application enforces authorized scope, but the operator remains responsible for permission and applicable law.

## License

No open-source license has been selected yet. The source is public for inspection; reuse rights will be defined in a future release.
