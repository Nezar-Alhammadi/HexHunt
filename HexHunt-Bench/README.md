# HexHunt Bench

Independent evaluation harness for HexHunt Recon. It runs the real HexHunt Core against owned local labs, compares persisted results with explicit ground truth, and stores measurements in a Bench-owned SQLite database.

## Public Recon Gold Suite

- 12 public base cases and five deterministic variants per case: 60 effective targets.
- Coverage includes JavaScript/API discovery, declared source maps, GraphQL, WebSockets, authentication surfaces, secrets, forms, SPA traffic, metadata files, and a clean control.
- Scoring covers weighted recall, evidence coverage, precision, action validity, stopping, efficiency, and safety.
- Hard failure gates cover incomplete runs, scope attempts, and fabricated evidence references.

Private transfer cases and their ground truth are excluded from this public repository so they remain useful for unbiased evaluation.

Bench reuses the OpenRouter credential saved by HexHunt. The key is never copied into Bench results.

## Run

```bash
npm install
npm run desktop:dev
```

Each evaluation may incur OpenRouter usage. The application never starts paid runs automatically.

In **Results**, open a public result and choose **Download redacted JSON summary** to share its scores and usage. See the [public summary format](./docs/public-result-summary.md) for the fields and a synthetic example.

## Evidence validation smoke test

From the repository root, run the HexHunt Core test that exercises the finish gate with a synthetic HTTP result. It uses an in-memory run store and needs no server, network access, or OpenRouter key once the build dependencies are installed.

```bash
cargo test --locked --manifest-path HexHunt/src-tauri/Cargo.toml --lib finish_gate_requires_evidence_stored_for_the_run
```

The test checks that a successful final output must cite an evidence ID stored for that run. Omitting the ID or citing it from another run is rejected.

## Evidence review and persistence baselines

Use the [offline baselines](./docs/offline-baselines.md) to compare evidence reviewers on fictional records and measure the time it takes HexHunt Core to persist an event as the run history grows.
