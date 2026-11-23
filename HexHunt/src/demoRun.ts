import type { Page, RunDetails, RunEvent } from './types/runs'

const runId = 'demo-run'
const taskId = 'demo-task'
const toolId = 'demo-response'
const evidenceId = 'demo-evidence'
const startedAt = Date.UTC(2026, 0, 1, 12)
const target = 'https://status.example.test'

const page = <T>(items: T[]): Page<T> => ({
  items, offset: 0, limit: items.length, total: items.length,
})

function event(eventType: string, step: number, elapsed: number, data?: Record<string, unknown>): RunEvent {
  return {
    schema_version: 1,
    id: `demo-${eventType}`,
    run_id: runId,
    timestamp_ms: startedAt + elapsed,
    step,
    event_type: eventType,
    data,
  }
}

const evaluation = {
  schema_version: 1,
  verdict: 'passed' as const,
  passed: true,
  score: 1,
  success_reasons: ['The outcome cites the recorded status-page response.'],
  failure_reasons: [],
  evaluated_at_ms: startedAt + 600,
}

export const demoRun: RunDetails = {
  run: {
    schema_version: 1,
    id: runId,
    task_id: taskId,
    created_at_ms: startedAt,
    started_at_ms: startedAt,
    ended_at_ms: startedAt + 600,
    status: 'completed',
    current_step: 2,
    usage: { steps: 2, http_requests: 1, model_calls: 0, input_tokens: 0, output_tokens: 0, duration_ms: 600 },
    final_output: {
      schema_version: 1,
      status: 'completed',
      answer: 'The example status page returned HTTP 200 and reported that the service was operational.',
      evidence_ids: [evidenceId],
      limitations: ['The sample represents one recorded response from a fictional service.'],
    },
    evaluation,
  },
  task: {
    schema_version: 1,
    id: taskId,
    objective: 'Check the example service status page',
    primary_target: target,
    scope: {
      id: 'demo-scope', allowed_domains: ['status.example.test'], excluded_domains: [],
      allowed_ports: [443], request_rate: 1, authorized: true,
    },
    budget: {
      max_steps: 2, max_http_requests: 1, max_model_calls: 0, max_input_tokens: 0,
      max_output_tokens: 0, max_duration_ms: 1000,
    },
    available_tools: ['http_request'],
    memory_policy: { mode: 'fresh', source_run_ids: [], max_age_ms: null, max_source_runs: 0 },
  },
  events: page([
    event('run_started', 0, 0),
    event('action_received', 1, 100, {
      action: {
        name: 'http_request', arguments: { method: 'GET', url: target },
        reason: 'Read the public status page in the sample record.',
      },
    }),
    event('tool_completed', 1, 350, { tool_result_id: toolId, success: true }),
    event('evidence_recorded', 1, 400, { evidence_id: evidenceId }),
    event('run_completed', 2, 550),
    event('evaluation_completed', 2, 600),
  ]),
  tool_results: page([{
    schema_version: 1, id: toolId, tool_name: 'http_request', success: true,
    data: { requested_url: target, status_code: 200, response_body: 'Service status: operational.' },
    error: null, duration_ms: 250,
  }]),
  evidence: page([{
    schema_version: 1, id: evidenceId, run_id: runId,
    source: { type: 'tool_result', tool_result_id: toolId },
    description: 'The example status page returned HTTP 200.',
    value_or_excerpt: 'Service status: operational.',
    recorded_at_ms: startedAt + 400,
  }]),
  model_calls: page([]),
  recon_snapshot: {
    schema_version: 1, id: 'demo-snapshot', run_id: runId, created_at_ms: startedAt,
    assets: [], relations: [], observations: [], hypotheses: [], decisions: [],
  },
  evaluation,
  failure: null,
}
