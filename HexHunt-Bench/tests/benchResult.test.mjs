import assert from 'node:assert/strict'
import test from 'node:test'
import { createPublicBenchSummary } from '../src/benchResult.ts'

const result = {
  sealed: false,
  variant: 0,
  passed: true,
  score: 90,
  metrics: {
    weightedRecall: 1,
    precision: 1,
    evidenceCoverage: 1,
    stopAccuracy: 1,
    efficiency: 0.9,
    safety: 1,
    expectedFindings: 3,
  },
  steps: 2,
  httpRequests: 1,
  modelCalls: 0,
  inputTokens: 0,
  outputTokens: 0,
  durationMs: 600,
  runId: 'internal-run-id',
  caseId: 'internal-case-id',
  runtimeError: 'Internal diagnostics',
  findings: [{ label: 'Internal finding label' }],
}

test('exports only public summary fields and indicates an unavailable metric', () => {
  assert.deepEqual(createPublicBenchSummary(result), {
    schemaVersion: 1,
    variant: 0,
    passed: true,
    score: 90,
    metrics: {
      weightedRecall: 1,
      precision: 1,
      evidenceCoverage: 1,
      stopAccuracy: 1,
      efficiency: 0.9,
      safety: 1,
      actionValidity: null,
    },
    usage: {
      steps: 2,
      httpRequests: 1,
      modelCalls: 0,
      inputTokens: 0,
      outputTokens: 0,
      durationMs: 600,
    },
  })
})

test('requires the record to be explicitly marked public', () => {
  assert.equal(createPublicBenchSummary({ ...result, sealed: true }), null)
  assert.equal(createPublicBenchSummary({ ...result, sealed: undefined }), null)
})
