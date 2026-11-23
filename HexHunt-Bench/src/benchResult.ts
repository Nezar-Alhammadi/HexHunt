interface FindingResult {
  id: string
  label: string
  category: string
  detected: boolean
  evidenceBacked: boolean
  weight: number
}

interface BenchMetrics {
  weightedRecall: number
  precision: number
  evidenceCoverage: number
  stopAccuracy: number
  efficiency: number
  safety: number
  actionValidity?: number | null
  expectedFindings: number
  detectedFindings: number
  unexpectedHighSignalHypotheses: number
  invalidActions: number
  repeatedActions: number
  scopeViolationAttempts: number
  fabricatedEvidenceReferences: number
}

export interface BenchResult {
  resultId: string
  createdAtMs: number
  caseId: string
  caseTitle: string
  category: string
  variant: number
  sealed: boolean
  clean: boolean
  runId: string
  runStatus: string
  passed: boolean
  score: number
  metrics: BenchMetrics
  findings: FindingResult[]
  hardFailures: string[]
  actionRejections: string[]
  measurementWarnings: string[]
  runtimeError?: string
  steps: number
  httpRequests: number
  modelCalls: number
  inputTokens: number
  outputTokens: number
  durationMs: number
  model: string
  actualProviders: string[]
  promptVersion: number
}

export function createPublicBenchSummary(result: BenchResult) {
  if (result.sealed !== false) return null

  const metrics = result.metrics
  return {
    schemaVersion: 1,
    variant: result.variant,
    passed: result.passed,
    score: result.score,
    metrics: {
      weightedRecall: metrics.weightedRecall,
      precision: metrics.precision,
      evidenceCoverage: metrics.evidenceCoverage,
      stopAccuracy: metrics.stopAccuracy,
      efficiency: metrics.efficiency,
      safety: metrics.safety,
      actionValidity: metrics.actionValidity ?? null,
    },
    usage: {
      steps: result.steps,
      httpRequests: result.httpRequests,
      modelCalls: result.modelCalls,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      durationMs: result.durationMs,
    },
  }
}
