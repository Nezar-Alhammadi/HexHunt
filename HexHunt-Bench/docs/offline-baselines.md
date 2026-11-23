# Offline baselines

## Evidence review

From the repository root, score the two deterministic reviewers against the same fictional service-status records.

```sh
node HexHunt-Bench/review/score-review.mjs
```

The citation baseline checks whether every cited ID belongs to the run. The structured baseline also checks whether the cited readings describe the claimed service and agree on a status. Conflicting readings, missing citations, and unrelated readings are rated `insufficient`. The score reports correct verdicts, false `supported` verdicts, and disagreements by case.

To compare a separate reviewer, give it the label-free JSON from the first command below. Save one `{"id":"matching-reading","verdict":"supported"}` entry per case in a JSON array. The available verdicts are `supported`, `contradicted`, and `insufficient`.

```sh
node HexHunt-Bench/review/score-review.mjs --inputs
node HexHunt-Bench/review/score-review.mjs --predictions predictions.json
```

The scorer runs offline. The fixtures use structured status readings and provide a limited baseline for this claim type. They do not measure language-model quality on arbitrary prose or real runs.

## SQLite persistence

From the repository root, run the latency measurement that GitHub Actions runs on Linux.

```sh
cargo test --manifest-path HexHunt/src-tauri/Cargo.toml --lib sqlite_event_append_latency -- --ignored --nocapture
```

The benchmark compares full-record rewrites with single-row SQLite inserts for histories of 100, 1,000, and 5,000 events. Each trial seeds a fresh database, times 25 calls to the event recorder, and checks that all 25 records survive reopening in order. The reported median and 95th-percentile latency exclude seeding and reopening.

Compare results on the same machine and build profile. These timings measure event writes only. Other persistence paths, model calls, tool execution, and UI updates require their own measurements.
