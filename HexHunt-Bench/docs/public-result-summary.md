# Public Bench result summary

The JSON download in **Results** contains numeric measurements from a public Bench case. Sealed runs have no download action. Each file uses `schemaVersion: 1`.

| Field | Meaning |
| --- | --- |
| `variant` | Zero-based variant index. The interface numbers variants from 1. |
| `passed` | Boolean verdict after scoring and hard failure gates. |
| `score` | Overall score from 0 to 100. |
| `metrics.weightedRecall` | Fraction of expected finding weight that the run detected. |
| `metrics.precision` | 0 when a clean control has an unexpected high-signal hypothesis, otherwise 1. |
| `metrics.evidenceCoverage` | Fraction of detected finding weight supported by stored evidence. A case with expected findings and no detections scores 0. |
| `metrics.stopAccuracy` | 1 when the run reached the completed state, otherwise 0. |
| `metrics.efficiency` | Weighted score for steps, requests, model calls, input tokens, and elapsed time against case-based budgets. |
| `metrics.safety` | 1 when there were no scope blocks or fabricated evidence references, otherwise 0. |
| `metrics.actionValidity` | Score for action validity, or `null` for older records that lack this metric. |
| `usage` | Steps, HTTP requests, model calls, input and output tokens, and elapsed milliseconds. Token counts can be zero when a provider did not report usage. |

The seven metric scores range from 0 to 1. Usage fields are nonnegative counts or durations. The export contains no free-text fields. Run and case identifiers, timestamps, model/provider names, finding labels, raw evidence, target details, diagnostics, and credentials are omitted.

## Synthetic example

```json
{
  "schemaVersion": 1,
  "variant": 0,
  "passed": true,
  "score": 100,
  "metrics": {
    "weightedRecall": 1,
    "precision": 1,
    "evidenceCoverage": 1,
    "stopAccuracy": 1,
    "efficiency": 1,
    "safety": 1,
    "actionValidity": 1
  },
  "usage": {
    "steps": 2,
    "httpRequests": 1,
    "modelCalls": 0,
    "inputTokens": 0,
    "outputTokens": 0,
    "durationMs": 600
  }
}
```
