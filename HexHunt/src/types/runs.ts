export type RunStatus = 'created' | 'running' | 'completed' | 'failed' | 'cancelled' | 'budget_exhausted' | 'scope_blocked'
export type EvaluationVerdict = 'passed' | 'failed' | 'inconclusive'

export type Scope = {
  id: string
  allowed_domains: string[]
  excluded_domains: string[]
  allowed_ports: number[]
  request_rate: number
  authorized: boolean
}

export type RunUsage = {
  steps: number
  http_requests: number
  model_calls: number
  input_tokens: number
  output_tokens: number
  duration_ms: number
}

export type TaskBudget = {
  max_steps: number
  max_http_requests: number
  max_model_calls: number
  max_input_tokens: number
  max_output_tokens: number
  max_duration_ms: number
}

export type RunMemoryMode = 'fresh' | 'continue' | 'auto_assisted'

export type RunMemoryPolicy = {
  mode: RunMemoryMode
  source_run_ids: string[]
  max_age_ms: number | null
  max_source_runs: number
}

export type Task = {
  schema_version: number
  id: string
  objective: string
  primary_target: string
  scope: Scope
  budget: TaskBudget
  available_tools: string[]
  memory_policy: RunMemoryPolicy
}

export type FinalOutput = {
  schema_version: number
  status: 'completed' | 'inconclusive' | 'budget_exhausted' | 'error'
  answer: string
  evidence_ids: string[]
  limitations: string[]
}

export type EvaluationResult = {
  schema_version: number
  verdict: EvaluationVerdict
  passed: boolean
  score: number | null
  success_reasons: string[]
  failure_reasons: string[]
  evaluated_at_ms: number
}

export type Run = {
  schema_version: number
  id: string
  task_id: string
  created_at_ms: number
  started_at_ms: number | null
  ended_at_ms: number | null
  status: RunStatus
  current_step: number
  usage: RunUsage
  final_output: FinalOutput | null
  evaluation: EvaluationResult | null
}

export type RunEvent = {
  schema_version: number
  id: string
  run_id: string
  timestamp_ms: number
  step: number
  event_type: string
  data?: Record<string, unknown>
}

export type ToolResult = {
  schema_version: number
  id: string
  tool_name: string
  success: boolean
  data: Record<string, unknown>
  error: { code: string; message: string; retryable: boolean } | null
  duration_ms: number
}

export type Evidence = {
  schema_version: number
  id: string
  run_id: string
  source: { type: string; tool_result_id?: string; model_call_id?: string; request_id?: string }
  description: string
  value_or_excerpt: string
  recorded_at_ms: number
}

export type ModelCallRecord = {
  schema_version: number
  id: string
  run_id: string
  provider: string
  model: string
  api_response_model: string | null
  actual_provider: string | null
  quantization: string | null
  reasoning_effort: string | null
  temperature: number | null
  max_output_tokens: number
  seed: number | null
  prompt_id: string
  prompt_version: number
  prompt_hash: string
  started_at_ms: number
  success: boolean
  request_count: number
  attempt_number: number
  input_tokens: number
  output_tokens: number
  reasoning_tokens: number
  usage_reported: boolean
  duration_ms: number
  error: { code: string; message: string; retryable: boolean } | null
}

export type Page<T> = { items: T[]; offset: number; limit: number; total: number }
export type RunListItem = { run: Run; task_title: string; evaluation_verdict: EvaluationVerdict | null; model: string | null }
export type RunFailure = { code: string; message: string }
export type ReconAsset = {
  schema_version: number; id: string; kind: string; canonical_value: string; display_name: string | null
  scope: string; scope_reason: string; confidence: string; first_seen_at_ms: number; last_seen_at_ms: number; tags: string[]
}
export type ReconObservation = {
  schema_version: number; id: string; run_id: string; source: string; subject_asset_ids: string[]
  summary: string; facts: Record<string, unknown>; confidence: string; evidence_ids: string[]; observed_at_ms: number
}
export type ReconHypothesis = {
  schema_version: number; id: string; kind: string | null; statement: string; status: string; subject_asset_ids: string[]
  rationale: string; confidence: string; priority: string | null; recommended_capability: string | null
  supporting_observation_ids: string[]; contradicting_observation_ids: string[]
}
export type ReconKnowledgeGap = { schema_version: number; id: string; asset_id: string; capability: string; description: string; priority: string; actionable: boolean; blocked_reason: string | null }
export type ReconDecision = {
  schema_version: number; run_id: string; step: number; mode: string; hypothesis_id: string | null
  knowledge_gaps: ReconKnowledgeGap[]; candidate_actions: Array<Record<string, unknown>>
  action_scores: Array<Record<string, unknown>>; recommended_action_id: string | null; selected_action_id: string | null
  coverage: { in_scope_assets: number; observed_assets: number; actionable_gaps: number; blocked_gaps: number; coverage_percent: number; active_hypotheses: number; supported_hypotheses: number; review_ready: boolean } | null
  decision_summary: string; stop_reason_code: string | null; stop_reason: string | null
}
export type ReconSnapshot = {
  schema_version: number; id: string; run_id: string; created_at_ms: number; assets: ReconAsset[]
  relations: Array<Record<string, unknown>>; observations: ReconObservation[]; hypotheses: ReconHypothesis[]; decisions: ReconDecision[]
}
export type RunDetails = {
  run: Run
  task: Task
  events: Page<RunEvent>
  tool_results: Page<ToolResult>
  evidence: Page<Evidence>
  model_calls: Page<ModelCallRecord>
  recon_snapshot: ReconSnapshot
  evaluation: EvaluationResult | null
  failure: RunFailure | null
}

export type TauriCommandError = { code: string; message: string }
