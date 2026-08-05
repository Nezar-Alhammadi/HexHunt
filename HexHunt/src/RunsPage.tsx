import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, ArrowLeft, CheckCircle2, CircleDot, RefreshCw, ShieldAlert, Wrench } from 'lucide-react'
import { getRunDetails, listRuns, normalizeRunError } from './api/runs'
import { CopyButton, EmptyState, ErrorState, JsonViewer, LoadingState, MetricCard, PageHeader, StatusBadge, Tabs, formatDuration, formatTime, humanize, shortId } from './components/ui'
import type { EvaluationVerdict, Evidence, RunDetails, RunEvent, RunListItem, RunStatus, ToolResult } from './types/runs'

type RunTab = 'overview' | 'timeline' | 'tools' | 'evidence' | 'models' | 'evaluation' | 'raw'
type Props = {
  selectedRunId: string | null
  onSelectRun: (runId: string | null) => void
  executionError?: string
  returnToExperiment?: { id: string; name?: string } | null
  onReturnToExperiment?: () => void
}

const terminalStatuses: RunStatus[] = ['completed', 'failed', 'cancelled', 'budget_exhausted', 'scope_blocked']
const tabItems: Array<{ value: RunTab; label: string }> = [
  { value: 'overview', label: 'Overview' }, { value: 'timeline', label: 'Timeline' },
  { value: 'tools', label: 'Tools' }, { value: 'evidence', label: 'Evidence' },
  { value: 'models', label: 'Model Calls' }, { value: 'evaluation', label: 'Evaluation' }, { value: 'raw', label: 'Raw' },
]

export default function RunsPage({ selectedRunId, onSelectRun, executionError, returnToExperiment, onReturnToExperiment }: Props) {
  const [runs, setRuns] = useState<RunListItem[]>([])
  const [listLoading, setListLoading] = useState(true)
  const [details, setDetails] = useState<RunDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(executionError ?? '')
  const [tab, setTab] = useState<RunTab>('overview')
  const [status, setStatus] = useState('all')
  const [verdict, setVerdict] = useState('all')
  const [model, setModel] = useState('all')
  const [search, setSearch] = useState('')

  const loadList = useCallback(async () => {
    try { setRuns((await listRuns()).items); setError('') }
    catch (cause) { const value = normalizeRunError(cause); setError(`${value.code}: ${value.message}`) }
    finally { setListLoading(false) }
  }, [])
  const loadDetails = useCallback(async (runId: string, quiet = false) => {
    if (!quiet) setLoading(true)
    try { setDetails(await getRunDetails(runId)); setError('') }
    catch (cause) { const value = normalizeRunError(cause); setError(`${value.code}: ${value.message}`) }
    finally { if (!quiet) setLoading(false) }
  }, [])

  useEffect(() => { void loadList() }, [loadList])
  useEffect(() => { if (selectedRunId) { setTab('overview'); void loadDetails(selectedRunId) } else setDetails(null) }, [selectedRunId, loadDetails])
  useEffect(() => {
    if (!selectedRunId || !details || !['created', 'running'].includes(details.run.status)) return
    const timer = window.setInterval(() => { void loadDetails(selectedRunId, true); void loadList() }, 1500)
    return () => window.clearInterval(timer)
  }, [selectedRunId, details?.run.status, loadDetails, loadList])
  useEffect(() => { if (executionError) setError(executionError) }, [executionError])

  const models = useMemo(() => [...new Set(runs.map((item) => item.model).filter(Boolean) as string[])], [runs])
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return runs.filter((item) => (status === 'all' || item.run.status === status)
      && (verdict === 'all' || item.evaluation_verdict === verdict)
      && (model === 'all' || item.model === model)
      && (!query || item.run.id.toLowerCase().includes(query) || item.task_title.toLowerCase().includes(query)))
  }, [runs, status, verdict, model, search])

  const refresh = () => { void loadList(); if (selectedRunId) void loadDetails(selectedRunId) }

  return <div className="runs-page">
    <PageHeader icon={<Activity size={19}/>} title="Runs" description="See whether a run succeeded, then inspect only the evidence you need." actions={<button className="button secondary" onClick={refresh}><RefreshCw size={14}/>Refresh</button>}/>
    {returnToExperiment && onReturnToExperiment ? <button className="context-return" onClick={onReturnToExperiment}><ArrowLeft size={14}/>Return to experiment {returnToExperiment.name ?? shortId(returnToExperiment.id)}</button> : null}
    {error ? <ErrorState error={error}/> : null}
    <div className="runs-layout">
      <section className="panel runs-list-panel">
        <div className="panel-heading"><div><h2>Run history</h2><p>{filtered.length} visible of {runs.length}</p></div></div>
        <div className="run-filters">
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search task or Run ID" aria-label="Search runs"/>
          <select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status"><option value="all">All statuses</option>{(['created','running',...terminalStatuses] as string[]).map((value) => <option key={value} value={value}>{humanize(value)}</option>)}</select>
          <select value={verdict} onChange={(event) => setVerdict(event.target.value)} aria-label="Filter by verdict"><option value="all">All evaluations</option>{(['passed','failed','inconclusive'] as EvaluationVerdict[]).map((value) => <option key={value}>{humanize(value)}</option>)}</select>
          <select value={model} onChange={(event) => setModel(event.target.value)} aria-label="Filter by model"><option value="all">All models</option>{models.map((value) => <option key={value}>{value}</option>)}</select>
        </div>
        <div className="run-list">
          {filtered.map((item) => <button key={item.run.id} className={`run-row ${selectedRunId === item.run.id ? 'selected' : ''}`} onClick={() => onSelectRun(item.run.id)}>
            <div className="run-row-main"><span className="run-id">{shortId(item.run.id)}</span><StatusBadge value={item.run.status}/><strong>{item.task_title}</strong><small>{item.model ?? 'Model not recorded'}</small></div>
            <div className="run-row-metrics"><span>{formatDuration(item.run.usage.duration_ms)}</span><span>{item.run.usage.steps} steps</span><span>{item.run.usage.http_requests} HTTP</span><span>{item.run.usage.model_calls} calls</span></div>
            <div className="run-row-meta"><StatusBadge value={item.evaluation_verdict ?? 'not_evaluated'} tone={item.evaluation_verdict === 'passed' ? 'success' : item.evaluation_verdict === 'failed' ? 'danger' : 'neutral'}/><time>{formatTime(item.run.created_at_ms)}</time></div>
          </button>)}
          {listLoading ? <LoadingState label="Loading Run history…"/> : !runs.length ? <EmptyState title="No runs yet" description="Open Agent, enter a task, and start your first scoped run."/> : !filtered.length ? <EmptyState title="No matching runs" description="Clear one or more filters to see the saved run history."/> : null}
        </div>
      </section>

      <section className="panel run-detail-panel">
        {loading ? <LoadingState label="Loading the selected run…"/> : details ? <RunDetail details={details} tab={tab} onTab={setTab}/> : <EmptyState title="Select a run" description="Choose a run on the left to see its outcome first, then inspect timeline, tools, and evidence."/>}
      </section>
    </div>
  </div>
}

function RunDetail({ details, tab, onTab }: { details: RunDetails; tab: RunTab; onTab: (tab: RunTab) => void }) {
  const model = details.model_calls.items.at(-1)?.model ?? 'Not recorded'
  return <>
    <header className="run-summary-header">
      <div className="run-summary-title"><div><span>Run {shortId(details.run.id)}</span><h2>{details.task.objective}</h2><p>{model}</p></div><StatusBadge value={details.run.status}/></div>
      <div className="run-summary-metrics"><span><small>Duration</small>{formatDuration(details.run.usage.duration_ms)}</span><span><small>Steps</small>{details.run.usage.steps}</span><span><small>HTTP</small>{details.run.usage.http_requests}</span><span><small>Model calls</small>{details.run.usage.model_calls}</span><span><small>Evaluation</small>{details.evaluation ? humanize(details.evaluation.verdict) : 'Pending'}</span></div>
    </header>
    <Tabs value={tab} items={tabItems.map((item) => ({ ...item, count: item.value === 'timeline' ? details.events.total : item.value === 'tools' ? details.tool_results.total : item.value === 'evidence' ? details.evidence.total : item.value === 'models' ? details.model_calls.total : undefined }))} onChange={onTab}/>
    <div className="tab-content">
      {tab === 'overview' ? <Overview details={details} onTab={onTab}/> : null}
      {tab === 'timeline' ? <Timeline events={details.events.items}/> : null}
      {tab === 'tools' ? <ToolResults results={details.tool_results.items}/> : null}
      {tab === 'evidence' ? <EvidenceView evidence={details.evidence.items} onTool={(id) => { onTab('tools'); window.setTimeout(() => document.getElementById(`tool-${id}`)?.scrollIntoView({ behavior: 'smooth' }), 50) }}/> : null}
      {tab === 'models' ? <ModelCalls details={details}/> : null}
      {tab === 'evaluation' ? <Evaluation details={details}/> : null}
      {tab === 'raw' ? <div className="raw-gate"><h3>Complete technical record</h3><p>Use this only when the summarized tabs do not answer your question.</p><JsonViewer value={details} label="Reveal raw Run JSON"/></div> : null}
    </div>
  </>
}

function Overview({ details, onTab }: { details: RunDetails; onTab: (tab: RunTab) => void }) {
  const output = details.run.final_output
  const next = details.run.status === 'completed' ? (details.evidence.total ? 'Review the evidence supporting the answer.' : 'Review the evaluation before relying on this result.') : 'Open Timeline to find where the run stopped.'
  return <div className="overview-stack">
    <section className={`decision-card ${details.evaluation?.passed ? 'success' : details.run.status === 'failed' ? 'danger' : ''}`}><div><span>Outcome</span><h3>{details.evaluation?.passed ? 'The run passed evaluation' : details.run.status === 'completed' ? 'The run finished but needs review' : `The run ${humanize(details.run.status).toLowerCase()}`}</h3><p>{output?.answer ?? details.failure?.message ?? 'No final answer was saved.'}</p></div><StatusBadge value={details.evaluation?.verdict ?? details.run.status}/></section>
    <section className="next-action"><strong>Next step</strong><p>{next}</p><button className="button secondary" onClick={() => onTab(details.run.status === 'completed' ? (details.evidence.total ? 'evidence' : 'evaluation') : 'timeline')}>Open recommended section</button></section>
    <div className="metric-grid"><MetricCard label="Steps" value={details.run.usage.steps}/><MetricCard label="HTTP requests" value={details.run.usage.http_requests}/><MetricCard label="Model calls" value={details.run.usage.model_calls}/><MetricCard label="Tokens" value={`${details.run.usage.input_tokens} in / ${details.run.usage.output_tokens} out`}/></div>
    <div className="summary-grid"><section><h3>Authorized target</h3><p className="wrap-value">{details.task.primary_target}</p><details><summary>Scope boundaries</summary><p>{details.task.scope.allowed_domains.join(', ') || 'No domains listed'}</p><p>Ports: {details.task.scope.allowed_ports.join(', ')}</p></details></section><section><h3>Evidence coverage</h3><p>{details.evidence.total} evidence item{details.evidence.total === 1 ? '' : 's'} linked to {details.tool_results.total} tool result{details.tool_results.total === 1 ? '' : 's'}.</p><button className="text-link simple" onClick={() => onTab('evidence')}>Review evidence</button></section></div>
  </div>
}

function Timeline({ events }: { events: RunEvent[] }) {
  if (!events.length) return <EmptyState title="No events recorded" description="This Run has no timeline entries to review."/>
  return <div className="timeline">{events.map((event) => {
    const important = ['action_rejected','scope_blocked','run_failed'].includes(event.event_type)
    return <article className={important ? 'important' : ''} key={event.id}><span className="event-icon">{eventIcon(event.event_type)}</span><div className="event-copy"><div><strong>{humanize(event.event_type)}</strong><StatusBadge value={`step_${event.step}`} tone="neutral"/><time>{formatTime(event.timestamp_ms)}</time></div>{important ? <p>{eventMessage(event)}</p> : null}<JsonViewer value={event.data ?? {}} label="Show event payload"/></div></article>
  })}</div>
}

function ToolResults({ results }: { results: ToolResult[] }) {
  if (!results.length) return <EmptyState title="No tools were executed" description="The Agent finished or stopped before a tool produced a result."/>
  return <div className="result-list">{results.map((result) => {
    const body = String(result.data.response_body ?? '')
    const redacted = JSON.stringify(result.data).includes('[REDACTED]')
    return <article id={`tool-${result.id}`} key={result.id} className="result-card"><header><div><Wrench size={15}/><strong>{humanize(result.tool_name)}</strong></div><div><StatusBadge value={result.success ? 'success' : 'failed'}/><span>{formatDuration(result.duration_ms)}</span></div></header>
      {result.tool_name === 'http_request' ? <><div className="http-summary"><code>{String(result.data.method ?? 'HTTP')}</code><span className="wrap-value">{String(result.data.requested_url ?? '')}</span><StatusBadge value={`http_${String(result.data.status_code ?? 'unknown')}`} tone={Number(result.data.status_code) >= 400 ? 'warning' : 'success'}/></div><div className="result-flags">{result.data.response_body_truncated ? <StatusBadge value="truncated" tone="warning"/> : null}{redacted ? <StatusBadge value="redacted" tone="info"/> : null}</div><JsonViewer value={result.data.response_headers ?? {}} label="Response headers"/><details><summary>Response body</summary><div className="copy-row">{!redacted ? <CopyButton value={body}/> : null}</div><pre className="body-viewer">{body || 'Empty response body'}</pre></details></> : <JsonViewer value={result.data}/>} {result.error ? <ErrorState error={`${result.error.code}: ${result.error.message}`} title="Tool execution failed"/> : null}
    </article>
  })}</div>
}

function EvidenceView({ evidence, onTool }: { evidence: Evidence[]; onTool: (id: string) => void }) {
  if (!evidence.length) return <EmptyState title="No evidence was saved" description="Review Timeline to see whether the Agent finished early or the tool result could not be recorded."/>
  return <div className="result-list">{evidence.map((item) => <article className="result-card evidence-card" key={item.id}><header><div><CheckCircle2 size={15}/><strong>{item.description}</strong></div><code>{shortId(item.id)}</code></header><p>{item.value_or_excerpt}</p><div className="evidence-source"><span>Source</span><StatusBadge value={item.source.type} tone="info"/>{item.source.tool_result_id ? <button className="text-link simple" onClick={() => onTool(item.source.tool_result_id!)}>Open source ToolResult</button> : null}</div></article>)}</div>
}

function ModelCalls({ details }: { details: RunDetails }) {
  if (!details.model_calls.items.length) return <EmptyState title="No model calls recorded" description="The Run stopped before contacting the configured model."/>
  return <div className="result-list">{details.model_calls.items.map((call) => <article className="result-card" key={call.id}><header><div><CircleDot size={15}/><strong>{call.provider} · {call.model}</strong></div><StatusBadge value={call.success ? 'success' : 'failed'}/></header><div className="model-call-grid"><span><small>Duration</small>{formatDuration(call.duration_ms)}</span><span><small>Attempt</small>{call.attempt_number}</span><span><small>Input</small>{call.input_tokens}</span><span><small>Output</small>{call.output_tokens}</span><span><small>Reasoning</small>{call.reasoning_tokens}</span><span><small>Effort</small>{call.reasoning_effort ?? 'Unknown'}</span></div>{call.error ? <ErrorState error={`${call.error.code}: ${call.error.message}`} title="Model call failed"/> : null}</article>)}</div>
}

function Evaluation({ details }: { details: RunDetails }) {
  if (!details.evaluation) return <EmptyState title="Evaluation is not available" description="The Run may still be active or ended before a final output could be evaluated."/>
  const value = details.evaluation
  return <div className="evaluation-view"><section className="decision-card"><div><span>Automated verdict</span><h3>{value.passed ? 'Passed' : humanize(value.verdict)}</h3><p>{value.passed ? 'The final output and its evidence references satisfied the current evaluator.' : 'The result should not be treated as a verified success.'}</p></div><StatusBadge value={value.verdict}/></section><div className="evaluation-columns"><section><h3>What passed</h3>{value.success_reasons.length ? <ul>{value.success_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>No success reasons were recorded.</p>}</section><section><h3>What needs attention</h3>{value.failure_reasons.length ? <ul>{value.failure_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>No failure reasons were recorded.</p>}</section></div></div>
}

function eventIcon(type: string) { return ['action_rejected','scope_blocked','run_failed'].includes(type) ? <ShieldAlert size={15}/> : <CircleDot size={13}/> }
function eventMessage(event: RunEvent) { const data = event.data ?? {}; return String(data.reason ?? (data.error as Record<string, unknown> | undefined)?.message ?? 'This event interrupted or constrained the run.') }
