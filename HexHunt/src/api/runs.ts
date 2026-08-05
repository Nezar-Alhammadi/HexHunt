import { invoke } from '@tauri-apps/api/core'
import type {
  EvaluationResult,
  Evidence,
  ModelCallRecord,
  Page,
  Run,
  RunDetails,
  RunEvent,
  RunListItem,
  Task,
  TauriCommandError,
  ToolResult,
} from '../types/runs'

const requireDesktop = () => {
  if (!('__TAURI_INTERNALS__' in window)) {
    throw { code: 'DESKTOP_RUNTIME_REQUIRED', message: 'Run monitoring requires the HexHunt desktop application.' } satisfies TauriCommandError
  }
}

export const normalizeRunError = (error: unknown): TauriCommandError => {
  if (typeof error === 'object' && error !== null) {
    const value = error as Record<string, unknown>
    if (typeof value.code === 'string' && typeof value.message === 'string') {
      return { code: value.code, message: value.message }
    }
  }
  return { code: 'UNKNOWN_ERROR', message: error instanceof Error ? error.message : String(error) }
}

export async function listRuns(offset = 0, limit = 100): Promise<Page<RunListItem>> {
  requireDesktop()
  return invoke<Page<RunListItem>>('list_runs', { offset, limit })
}

export async function getRunDetails(runId: string, offset = 0, limit = 50): Promise<RunDetails> {
  requireDesktop()
  return invoke<RunDetails>('get_run_details', { runId, offset, limit })
}

export async function getRun(runId: string): Promise<Run> {
  requireDesktop()
  return invoke<Run>('get_run', { runId })
}

export const getRunEvents = (runId: string, offset = 0, limit = 200) =>
  invoke<Page<RunEvent>>('get_run_events', { runId, offset, limit })

export const getToolResults = (runId: string, offset = 0, limit = 100) =>
  invoke<Page<ToolResult>>('get_tool_results', { runId, offset, limit })

export const getEvidence = (runId: string, offset = 0, limit = 100) =>
  invoke<Page<Evidence>>('get_evidence', { runId, offset, limit })

export const getModelCalls = (runId: string, offset = 0, limit = 100) =>
  invoke<Page<ModelCallRecord>>('get_model_calls', { runId, offset, limit })

export const getEvaluationResult = (runId: string) =>
  invoke<EvaluationResult | null>('get_evaluation_result', { runId })

export const getTaskForRun = (runId: string) =>
  invoke<Task>('get_task_for_run', { runId })

export async function createRun(task: Task): Promise<Run> {
  requireDesktop()
  return invoke<Run>('create_run', { task })
}

export async function executeAgentRun(runId: string): Promise<void> {
  requireDesktop()
  await invoke('execute_agent_run', { runId })
}
