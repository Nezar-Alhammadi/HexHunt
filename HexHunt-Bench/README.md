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
