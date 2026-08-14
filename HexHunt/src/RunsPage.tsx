import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import {
  Activity, AlertTriangle, ArrowDown, ArrowLeft, Bot, BrainCircuit, CheckCircle2,
  CircleDot, Compass, Eye, FileSearch, FlaskConical, Globe2, Image, LoaderCircle, Network,
  Pause, Play, Radio, RefreshCw, Route, Search, Send, ShieldAlert, Square, Target, TerminalSquare,
  Wrench, Zap,
} from 'lucide-react'
import { cancelRun, getRunDetails, getVisualArtifact, listRuns, normalizeRunError } from './api/runs'
import { EmptyState, ErrorState, JsonViewer, LoadingState, StatusBadge, formatDuration, formatTime, humanize, shortId } from './components/ui'
import type { Evidence, ModelCallRecord, ReconDecision, ReconHypothesis, RunDetails, RunEvent, RunListItem, RunStatus, ToolResult } from './types/runs'

type TheaterView = 'live' | 'evidence' | 'report' | 'inspector'
type Props = {
  selectedRunId: string | null
  onSelectRun: (runId: string | null) => void
  executionError?: string
  returnToExperiment?: { id: string; name?: string } | null
  onReturnToExperiment?: () => void
}

const terminalStatuses: RunStatus[] = ['completed', 'failed', 'cancelled', 'budget_exhausted', 'scope_blocked']
const isActive = (status: RunStatus) => status === 'created' || status === 'running'

export default function RunsPage({ selectedRunId, onSelectRun, executionError, returnToExperiment, onReturnToExperiment }: Props) {
  const [runs, setRuns] = useState<RunListItem[]>([])
  const [details, setDetails] = useState<RunDetails | null>(null)
  const [loading, setLoading] = useState(false)
  const [listLoading, setListLoading] = useState(true)
  const [error, setError] = useState(executionError ?? '')
  const [query, setQuery] = useState('')
  const [view, setView] = useState<TheaterView>('live')

  const loadList = useCallback(async () => {
    try { setRuns((await listRuns(0, 200)).items); setError('') }
    catch (cause) { const value = normalizeRunError(cause); setError(`${value.code}: ${value.message}`) }
    finally { setListLoading(false) }
  }, [])
  const loadDetails = useCallback(async (runId: string, quiet = false) => {
    if (!quiet) setLoading(true)
    try { setDetails(await getRunDetails(runId, 0, 500)); setError('') }
    catch (cause) { const value = normalizeRunError(cause); setError(`${value.code}: ${value.message}`) }
    finally { if (!quiet) setLoading(false) }
  }, [])

  useEffect(() => { void loadList() }, [loadList])
  useEffect(() => {
    setView('live')
    if (selectedRunId) void loadDetails(selectedRunId)
    else setDetails(null)
  }, [selectedRunId, loadDetails])
  useEffect(() => {
    if (!selectedRunId || !details || !isActive(details.run.status)) return
    const timer = window.setInterval(() => { void loadDetails(selectedRunId, true); void loadList() }, 850)
    return () => window.clearInterval(timer)
  }, [selectedRunId, details?.run.status, loadDetails, loadList])
  useEffect(() => { if (executionError) setError(executionError) }, [executionError])

  const filteredRuns = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return runs.filter((item) => !needle || item.task_title.toLowerCase().includes(needle) || item.run.id.toLowerCase().includes(needle))
  }, [query, runs])
  const refresh = () => { void loadList(); if (selectedRunId) void loadDetails(selectedRunId) }

  return <div className="run-theater-page">
    <header className="theater-page-header">
      <div><span className="live-kicker"><Radio size={13}/>Agent operations</span><h1>Run Theater</h1><p>Watch every decision, action, response, and piece of evidence in causal order.</p></div>
      <div className="theater-header-actions">
        {returnToExperiment && onReturnToExperiment ? <button className="button secondary" onClick={onReturnToExperiment}><ArrowLeft size={14}/>Experiment</button> : null}
        <button className="button secondary" onClick={refresh}><RefreshCw size={14}/>Refresh</button>
      </div>
    </header>
    {error ? <ErrorState error={error}/> : null}
    <div className="theater-shell">
      <RunRail runs={filteredRuns} selectedRunId={selectedRunId} query={query} onQuery={setQuery} onSelect={onSelectRun} loading={listLoading}/>
      <main className="theater-stage">
        {loading ? <LoadingState label="Opening the run theater…"/> : details ? <RunStage details={details} view={view} onView={setView} onRefresh={() => loadDetails(details.run.id, true)}/> : <TheaterEmpty/>}
      </main>
    </div>
  </div>
}

function RunRail({ runs, selectedRunId, query, onQuery, onSelect, loading }: { runs: RunListItem[]; selectedRunId: string | null; query: string; onQuery: (value: string) => void; onSelect: (id: string) => void; loading: boolean }) {
  return <aside className="run-rail panel">
    <div className="rail-heading"><div><strong>Operations</strong><span>{runs.length} recorded</span></div><Activity size={17}/></div>
    <label className="rail-search"><Search size={14}/><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Find a run…"/></label>
    <div className="rail-list">
      {runs.map((item) => <button key={item.run.id} className={`rail-run ${selectedRunId === item.run.id ? 'active' : ''}`} onClick={() => onSelect(item.run.id)}>
        <span className={`run-pulse ${isActive(item.run.status) ? 'active' : item.run.status}`}/>
        <span className="rail-run-copy"><strong>{item.task_title}</strong><small>{shortId(item.run.id)} · {formatTime(item.run.created_at_ms)}</small><span>{item.run.usage.steps} steps · {item.run.usage.http_requests} requests · {formatDuration(item.run.usage.duration_ms)}</span></span>
        <StatusBadge value={item.run.status}/>
      </button>)}
      {loading ? <LoadingState label="Loading operations…"/> : !runs.length ? <EmptyState title="No operations yet" description="Start an authorized run to watch the agent here."/> : null}
    </div>
  </aside>
}

function TheaterEmpty() {
  return <div className="theater-empty"><div className="empty-orbit"><Bot size={34}/><span/><span/><span/></div><h2>Select an operation</h2><p>The theater reconstructs the agent’s work as a readable story—not a wall of logs.</p><div><span><BrainCircuit size={15}/>Decisions</span><span><Globe2 size={15}/>Requests</span><span><Image size={15}/>Visuals</span><span><CheckCircle2 size={15}/>Evidence</span></div></div>
}

function RunStage({ details, view, onView, onRefresh }: { details: RunDetails; view: TheaterView; onView: (view: TheaterView) => void; onRefresh: () => void }) {
  const [stopping, setStopping] = useState(false)
  const stop = async () => {
    setStopping(true)
    try { await cancelRun(details.run.id); onRefresh() } finally { setStopping(false) }
  }
  const active = isActive(details.run.status)
  return <>
    <RunMission details={details} active={active} stopping={stopping} onStop={stop}/>
    <nav className="theater-views" aria-label="Run views">
      <ViewButton active={view === 'live'} onClick={() => onView('live')} icon={<Radio size={14}/>} label="Live operation" count={details.events.total}/>
      <ViewButton active={view === 'evidence'} onClick={() => onView('evidence')} icon={<CheckCircle2 size={14}/>} label="Evidence room" count={details.evidence.total}/>
      <ViewButton active={view === 'report'} onClick={() => onView('report')} icon={<FileSearch size={14}/>} label="Outcome"/>
      <ViewButton active={view === 'inspector'} onClick={() => onView('inspector')} icon={<TerminalSquare size={14}/>} label="Technical inspector"/>
    </nav>
    {view === 'live' ? <LiveOperation details={details}/> : null}
    {view === 'evidence' ? <EvidenceRoom details={details}/> : null}
    {view === 'report' ? <OutcomeRoom details={details}/> : null}
    {view === 'inspector' ? <TechnicalInspector details={details}/> : null}
  </>
}

function ViewButton({ active, onClick, icon, label, count }: { active: boolean; onClick: () => void; icon: ReactNode; label: string; count?: number }) {
  return <button className={active ? 'active' : ''} onClick={onClick}>{icon}<span>{label}</span>{count != null ? <b>{count}</b> : null}</button>
}

function RunMission({ details, active, stopping, onStop }: { details: RunDetails; active: boolean; stopping: boolean; onStop: () => void }) {
  const phase = currentPhase(details)
  return <header className="run-mission">
    <div className="mission-primary">
      <div className={`mission-state ${active ? 'active' : details.run.status}`}><span>{active ? <LoaderCircle className="spinning" size={20}/> : statusIcon(details.run.status)}</span><small>{active ? 'Agent is working' : 'Operation ended'}</small><strong>{humanize(details.run.status)}</strong></div>
      <div className="mission-copy"><span>RUN {shortId(details.run.id)}</span><h2>{details.task.objective}</h2><p><Target size={13}/>{details.task.primary_target}</p></div>
      {active
        ? <button className="stop-run" disabled={stopping} onClick={onStop}><Square size={12}/>{stopping ? 'Stopping…' : 'Stop safely'}</button>
        : <StatusBadge value={details.evaluation?.verdict ?? details.run.status}/>}
    </div>
    <div className="mission-telemetry">
      <Telemetry label="Current phase" value={phase.label} hint={phase.hint}/>
      <Telemetry label="Step" value={`${details.run.current_step} / ${details.task.budget.max_steps}`} hint={`${budgetPercent(details.run.current_step, details.task.budget.max_steps)}% step budget`}/>
      <Telemetry label="Model" value={details.model_calls.items.at(-1)?.model?.split('/').at(-1) ?? 'Waiting'} hint={`${details.run.usage.model_calls} calls`}/>
      <Telemetry label="Network" value={`${details.run.usage.http_requests} requests`} hint={`${details.tool_results.total} tool results`}/>
      <Telemetry label="Knowledge" value={`${details.recon_snapshot.assets.length} assets`} hint={`${details.recon_snapshot.hypotheses.length} hypotheses`}/>
      <Telemetry label="Evidence" value={String(details.evidence.total)} hint={`${details.recon_snapshot.observations.length} observations`}/>
    </div>
  </header>
}

function Telemetry({ label, value, hint }: { label: string; value: string; hint: string }) {
  return <div><small>{label}</small><strong>{value}</strong><span>{hint}</span></div>
}

function LiveOperation({ details }: { details: RunDetails }) {
  const [follow, setFollow] = useState(true)
  const [showRoutine, setShowRoutine] = useState(true)
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => { if (follow) endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }) }, [details.events.total, details.tool_results.total, follow])
  const steps = useMemo(() => buildSteps(details, showRoutine), [details, showRoutine])
  return <div className="operation-grid">
    <section className="operation-film">
      <div className="film-toolbar">
        <div><span className={isActive(details.run.status) ? 'live-dot' : 'recorded-dot'}/><strong>{isActive(details.run.status) ? 'LIVE' : 'RECORDED'}</strong><small>{details.events.total} events reconstructed into {steps.length} scenes</small></div>
        <div><button className={showRoutine ? 'active' : ''} onClick={() => setShowRoutine(!showRoutine)}><Activity size={13}/>Routine events</button><button className={follow ? 'active' : ''} onClick={() => setFollow(!follow)}>{follow ? <Pause size={13}/> : <Play size={13}/>}Auto-follow</button></div>
      </div>
      <div className="film-reel">
        {steps.map((step) => <StepScene key={step.step} step={step} details={details}/>) }
        {isActive(details.run.status) ? <WorkingScene phase={currentPhase(details).label}/> : null}
        <div ref={endRef}/>
      </div>
    </section>
    <SituationPanel details={details}/>
  </div>
}

type StepBundle = { step: number; events: RunEvent[]; decision?: ReconDecision; tools: ToolResult[]; evidence: Evidence[]; modelCalls: ModelCallRecord[] }

function buildSteps(details: RunDetails, showRoutine: boolean): StepBundle[] {
  const byStep = new Map<number, StepBundle>()
  const ensure = (step: number) => {
    if (!byStep.has(step)) byStep.set(step, { step, events: [], tools: [], evidence: [], modelCalls: [] })
    return byStep.get(step)!
  }
  details.events.items.forEach((event) => ensure(event.step).events.push(event))
  details.recon_snapshot.decisions.forEach((decision) => { ensure(decision.step).decision = decision })
  details.events.items.forEach((event) => {
    if (event.event_type === 'tool_completed') {
      const id = stringAt(event.data, 'tool_result_id')
      const result = details.tool_results.items.find((item) => item.id === id)
      if (result && !ensure(event.step).tools.some((item) => item.id === result.id)) ensure(event.step).tools.push(result)
    }
    if (event.event_type === 'evidence_recorded') {
      const id = stringAt(event.data, 'evidence_id')
      const evidence = details.evidence.items.find((item) => item.id === id)
      if (evidence) ensure(event.step).evidence.push(evidence)
    }
    if (event.event_type === 'model_called') {
      const id = stringAt(event.data, 'model_call_id')
      const call = details.model_calls.items.find((item) => item.id === id)
      if (call) ensure(event.step).modelCalls.push(call)
    }
  })
  let items = [...byStep.values()].sort((a, b) => a.step - b.step)
  if (!showRoutine) items = items.filter((item) => item.decision || item.tools.length || item.evidence.length || item.events.some((event) => ['action_received','action_rejected','scope_blocked','run_failed','run_completed','evaluation_completed'].includes(event.event_type)))
  return items
}

function StepScene({ step, details }: { step: StepBundle; details: RunDetails }) {
  const actionEvent = step.events.find((event) => event.event_type === 'action_received' || event.event_type === 'action_rejected')
  const action = recordAt(actionEvent?.data, 'action')
  const reason = typeof action?.reason === 'string' ? action.reason : step.decision?.decision_summary
  const terminal = step.events.find((event) => ['run_completed','run_failed','scope_blocked','budget_exhausted','run_cancelled'].includes(event.event_type))
  return <article className={`step-scene ${terminal ? 'terminal-scene' : ''}`}>
    <div className="scene-marker"><span>{step.step}</span><i/></div>
    <div className="scene-body">
      <header><div><small>SCENE {String(step.step).padStart(2, '0')}</small><strong>{sceneTitle(step)}</strong></div><time>{formatTime(step.events.at(0)?.timestamp_ms ?? details.run.created_at_ms)}</time></header>
      {step.modelCalls.map((call) => <ModelExchange key={call.id} call={call}/>) }
      {step.decision ? <PlannerDecision decision={step.decision} hypotheses={details.recon_snapshot.hypotheses}/> : null}
      {action ? <AgentChoice action={action} rejected={actionEvent?.event_type === 'action_rejected'} rejection={stringAt(actionEvent?.data, 'reason')} reason={reason}/> : null}
      {step.tools.map((tool) => <ToolExchange key={tool.id} tool={tool}/>) }
      {step.evidence.length ? <EvidenceStrip evidence={step.evidence}/> : null}
      {step.events.filter((event) => ['action_rejected','scope_blocked','budget_exhausted','run_failed','run_cancelled','run_completed','evaluation_completed'].includes(event.event_type)).map((event) => <SystemOutcome key={event.id} event={event}/>) }
      {!step.modelCalls.length && !step.decision && !action && !step.tools.length && !step.evidence.length ? <RoutineEvents events={step.events}/> : null}
    </div>
  </article>
}

function ModelExchange({ call }: { call: ModelCallRecord }) {
  return <div className="exchange-card model-exchange"><div className="exchange-rail"><Send size={15}/><span/><Bot size={15}/></div><div><span>MODEL EXCHANGE</span><strong>Context sent to {call.model}</strong><p>{call.success ? 'A structured action was received and validated.' : call.error?.message ?? 'The model call did not complete.'}</p><div className="exchange-stats"><b>{formatDuration(call.duration_ms)}</b><b>{call.input_tokens.toLocaleString()} in</b><b>{call.output_tokens.toLocaleString()} out</b><b>attempt {call.attempt_number}</b></div><details><summary>What was shared</summary><p>Mission, authorized scope, budgets, available tool schemas, relevant evidence, and the current Recon snapshot. Secrets and hidden chain-of-thought are not stored here.</p></details></div><StatusBadge value={call.success ? 'received' : 'failed'} tone={call.success ? 'success' : 'danger'}/></div>
}

function PlannerDecision({ decision, hypotheses }: { decision: ReconDecision; hypotheses: ReconHypothesis[] }) {
  const hypothesis = hypotheses.find((item) => item.id === decision.hypothesis_id)
  const coverage = decision.coverage
  return <div className="decision-exchange"><div className="decision-icon"><BrainCircuit size={17}/></div><div><span>RECON PLANNER · {humanize(decision.mode)}</span><strong>{decision.decision_summary || 'The planner refreshed its next move.'}</strong>{hypothesis ? <p><FlaskConical size={13}/><b>Active hypothesis:</b> {hypothesis.statement}</p> : null}<div className="decision-chips"><em>{decision.candidate_actions.length} candidates</em><em>{decision.knowledge_gaps.filter((gap) => gap.actionable).length} actionable gaps</em>{coverage ? <em>{coverage.coverage_percent}% coverage</em> : null}</div></div></div>
}

function AgentChoice({ action, rejected, rejection, reason }: { action: Record<string, unknown>; rejected: boolean; rejection: string; reason?: string }) {
  const name = typeof action.name === 'string' ? action.name : 'agent_action'
  const args = recordAt(action, 'arguments') ?? {}
  return <div className={`agent-choice ${rejected ? 'rejected' : ''}`}><div className="choice-head"><span><Compass size={15}/>{rejected ? 'ACTION BLOCKED' : 'AGENT CHOICE'}</span><StatusBadge value={name} tone={rejected ? 'danger' : 'info'}/></div><h4>{reason || `Use ${humanize(name)} to reduce uncertainty.`}</h4>{rejected && rejection ? <p className="choice-warning"><ShieldAlert size={14}/>{rejection}</p> : null}<ArgumentSummary arguments={args}/><details><summary>Structured action</summary><JsonViewer value={action} label="Reveal action contract"/></details></div>
}

function ArgumentSummary({ arguments: args }: { arguments: Record<string, unknown> }) {
  const entries = Object.entries(args).filter(([key]) => !/key|token|cookie|authorization|secret|password/i.test(key)).slice(0, 8)
  if (!entries.length) return null
  return <div className="argument-grid">{entries.map(([key, value]) => <div key={key}><small>{humanize(key)}</small><code>{summarize(value, 140)}</code></div>)}</div>
}

function ToolExchange({ tool }: { tool: ToolResult }) {
  const url = firstString(tool.data, ['requested_url','url','final_url','target'])
  const status = firstValue(tool.data, ['status_code','status','http_status'])
  const body = firstString(tool.data, ['response_body','body','content'])
  const views = Array.isArray(tool.data.identity_views) ? tool.data.identity_views as Array<Record<string, unknown>> : []
  const observation = recordAt(tool.data, 'visual_observation')
  const artifactId = typeof tool.data.screenshot_artifact_id === 'string' ? tool.data.screenshot_artifact_id : null
  return <div className={`tool-exchange ${tool.success ? '' : 'failed'}`}>
    <div className="tool-title"><span><Wrench size={15}/>TOOL EXECUTION</span><div><code>{humanize(tool.tool_name)}</code><StatusBadge value={tool.success ? 'completed' : 'failed'}/><small>{formatDuration(tool.duration_ms)}</small></div></div>
    {url ? <div className="wire-row"><span><Send size={13}/>Sent</span><code>{summarize(url, 240)}</code>{status != null ? <StatusBadge value={`HTTP ${String(status)}`} tone={Number(status) >= 400 ? 'warning' : 'success'}/> : null}</div> : null}
    {body ? <details className="response-preview"><summary><ArrowDown size={13}/>Received response preview</summary><pre>{body.slice(0, 2400)}</pre></details> : null}
    {views.length ? <BrowserFrames views={views}/> : null}
    {observation ? <VisualObservation observation={observation} artifactId={artifactId}/> : artifactId ? <VisualArtifact artifactId={artifactId}/> : null}
    {!body && !views.length && !observation ? <ResultFacts data={tool.data}/> : null}
    {tool.error ? <div className="tool-error"><AlertTriangle size={14}/><span><strong>{tool.error.code}</strong>{tool.error.message}</span></div> : null}
    <details className="payload-details"><summary>Open complete sanitized result</summary><JsonViewer value={tool.data} label="Reveal result data"/></details>
  </div>
}

function BrowserFrames({ views }: { views: Array<Record<string, unknown>> }) {
  return <div className="browser-frames">{views.map((view, index) => {
    const dom = recordAt(view, 'dom') ?? {}
    const events = Array.isArray(view.network_events) ? view.network_events as unknown[] : []
    return <div className="browser-frame" key={`${String(view.identity_id)}-${index}`}><div className="browser-chrome"><i/><i/><i/><span>{summarize(view.final_url, 130)}</span></div><div className="browser-frame-body"><div><Eye size={18}/><strong>{String(view.identity_name ?? 'anonymous')} view rendered</strong><p>{String(dom.title ?? 'Untitled page')}</p></div><div className="browser-metrics"><span>{arrayLength(dom.links)} links</span><span>{arrayLength(dom.forms)} forms</span><span>{events.length} network events</span><span>{String(dom.spa_root_detected) === 'true' ? 'SPA detected' : 'Static/unknown'}</span></div>{events.length ? <details><summary>Network activity</summary><div className="network-list">{events.slice(0, 12).map((event, eventIndex) => <NetworkEvent key={eventIndex} event={event}/>)}</div></details> : null}</div></div>
  })}</div>
}

function NetworkEvent({ event }: { event: unknown }) {
  const item = isRecord(event) ? event : {}
  return <div><Network size={12}/><StatusBadge value={String(item.status_code ?? 'unknown')} tone={Number(item.status_code) >= 400 ? 'warning' : 'success'}/><code>{summarize(item.url, 150)}</code><small>{humanize(String(item.resource_type ?? 'resource'))}</small></div>
}

function VisualObservation({ observation, artifactId }: { observation: Record<string, unknown>; artifactId: string | null }) {
  return <div className="visual-observation">{artifactId ? <VisualArtifact artifactId={artifactId}/> : <div className="visual-placeholder"><Image size={28}/><span>Visual analysis completed</span><small>The screenshot was not retained by this older run.</small></div>}<div><span>VISION OBSERVATION</span><strong>{String(observation.summary ?? 'The visual model inspected the rendered page.')}</strong><div className="visual-tags">{(['page_kind','confidence'] as const).map((key) => observation[key] ? <em key={key}>{humanize(String(observation[key]))}</em> : null)}{Array.isArray(observation.form_kinds) ? observation.form_kinds.map((item) => <em key={String(item)}>{humanize(String(item))}</em>) : null}</div></div></div>
}

function VisualArtifact({ artifactId }: { artifactId: string }) {
  const [source, setSource] = useState('')
  const [failed, setFailed] = useState(false)
  useEffect(() => { let live = true; void getVisualArtifact(artifactId).then((value) => { if (live) setSource(value) }).catch(() => { if (live) setFailed(true) }); return () => { live = false } }, [artifactId])
  if (failed) return <div className="visual-placeholder"><Image size={24}/><span>Screenshot unavailable</span><small>The local artifact could not be opened.</small></div>
  return <figure className="visual-artifact">{source ? <img src={source} alt="Redacted screenshot captured by HexHunt during the authorized run"/> : <div><LoaderCircle className="spinning" size={21}/>Loading captured frame…</div>}<figcaption><Eye size={12}/>Locally retained, redacted browser frame</figcaption></figure>
}

function ResultFacts({ data }: { data: Record<string, unknown> }) {
  const facts = Object.entries(data).filter(([key, value]) => !isSecretKey(key) && (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean')).slice(0, 8)
  return <div className="result-facts">{facts.map(([key, value]) => <div key={key}><small>{humanize(key)}</small><strong>{summarize(value, 160)}</strong></div>)}</div>
}

function EvidenceStrip({ evidence }: { evidence: Evidence[] }) {
  return <div className="evidence-strip"><div><CheckCircle2 size={15}/><strong>{evidence.length} evidence item{evidence.length === 1 ? '' : 's'} recorded</strong></div>{evidence.map((item) => <div className="evidence-line" key={item.id}><span>{shortId(item.id)}</span><p><strong>{item.description}</strong>{item.value_or_excerpt}</p></div>)}</div>
}

function SystemOutcome({ event }: { event: RunEvent }) {
  const dangerous = ['action_rejected','scope_blocked','run_failed','budget_exhausted'].includes(event.event_type)
  return <div className={`system-outcome ${dangerous ? 'danger' : 'success'}`}>{dangerous ? <ShieldAlert size={16}/> : <CheckCircle2 size={16}/>}<div><span>{humanize(event.event_type)}</span><strong>{eventMessage(event)}</strong></div></div>
}

function RoutineEvents({ events }: { events: RunEvent[] }) {
  return <div className="routine-events">{events.map((event) => <span key={event.id}><CircleDot size={11}/>{humanize(event.event_type)}</span>)}</div>
}

function WorkingScene({ phase }: { phase: string }) {
  return <article className="step-scene working-scene"><div className="scene-marker"><span><LoaderCircle className="spinning" size={15}/></span></div><div className="scene-body"><div className="working-wave"><i/><i/><i/><i/><i/></div><strong>{phase}</strong><p>HexHunt is waiting for the next persisted event. This view updates automatically.</p></div></article>
}

function SituationPanel({ details }: { details: RunDetails }) {
  const snapshot = details.recon_snapshot
  const latestDecision = snapshot.decisions.at(-1)
  const gaps = latestDecision?.knowledge_gaps ?? []
  return <aside className="situation-panel">
    <section><header><div><Route size={15}/><strong>Live plan</strong></div><StatusBadge value={latestDecision?.mode ?? 'initializing'} tone="info"/></header><p>{latestDecision?.decision_summary ?? 'The planner is building its first view of the target.'}</p>{latestDecision?.coverage ? <CoverageRing value={latestDecision.coverage.coverage_percent}/> : null}</section>
    <section><header><div><FlaskConical size={15}/><strong>Hypotheses</strong></div><b>{snapshot.hypotheses.length}</b></header><div className="hypothesis-stack">{snapshot.hypotheses.slice(-5).reverse().map((item) => <div key={item.id}><span className={`hypothesis-status ${item.status}`}/><p><strong>{item.statement}</strong><small>{humanize(item.status)} · {humanize(item.confidence)}</small></p></div>)}{!snapshot.hypotheses.length ? <p className="quiet-copy">No hypothesis has been formed yet.</p> : null}</div></section>
    <section><header><div><Target size={15}/><strong>Knowledge gaps</strong></div><b>{gaps.filter((gap) => gap.actionable).length}</b></header><div className="gap-stack">{gaps.slice(0, 5).map((gap) => <div key={gap.id}><Zap size={12}/><span><strong>{gap.description}</strong><small>{humanize(gap.capability)} · {humanize(gap.priority)}</small></span></div>)}{!gaps.length ? <p className="quiet-copy">No active gaps are recorded for this step.</p> : null}</div></section>
    <section><header><div><Globe2 size={15}/><strong>Asset graph</strong></div><b>{snapshot.assets.length}</b></header><div className="asset-cloud">{snapshot.assets.slice(-12).reverse().map((asset) => <span key={asset.id} title={asset.canonical_value}>{humanize(asset.kind)}<b>{asset.display_name ?? asset.canonical_value}</b></span>)}</div></section>
  </aside>
}

function CoverageRing({ value }: { value: number }) {
  return <div className="coverage-meter"><div style={{ '--coverage': `${Math.max(0, Math.min(100, value)) * 3.6}deg` } as CSSProperties}><strong>{value}%</strong><span>coverage</span></div></div>
}

function EvidenceRoom({ details }: { details: RunDetails }) {
  if (!details.evidence.items.length) return <EmptyState title="No evidence recorded yet" description="As tools produce verifiable observations, evidence will appear here with its source and Run link."/>
  return <div className="evidence-room"><header><div><span>EVIDENCE LEDGER</span><h3>What the agent can actually prove</h3><p>Every item is tied to this run and a recorded source. Conclusions without evidence remain hypotheses.</p></div><strong>{details.evidence.total}</strong></header><div>{details.evidence.items.map((item, index) => <article key={item.id}><span>{String(index + 1).padStart(2, '0')}</span><div><small>{humanize(item.source.type)} · {shortId(item.id)}</small><h4>{item.description}</h4><p>{item.value_or_excerpt}</p><details><summary>Traceability</summary><JsonViewer value={item.source} label="Reveal source reference"/></details></div><CheckCircle2 size={18}/></article>)}</div></div>
}

function OutcomeRoom({ details }: { details: RunDetails }) {
  const output = details.run.final_output
  const evaluation = details.evaluation
  return <div className="outcome-room"><section className={`outcome-hero ${evaluation?.passed ? 'passed' : details.run.status}`}><span>{evaluation?.passed ? <CheckCircle2 size={24}/> : <FileSearch size={24}/>}</span><div><small>FINAL OUTCOME</small><h3>{evaluation?.passed ? 'Verified result' : details.run.status === 'completed' ? 'Completed—review required' : `Run ${humanize(details.run.status).toLowerCase()}`}</h3><p>{output?.answer ?? details.failure?.message ?? 'No final answer was saved.'}</p></div><StatusBadge value={evaluation?.verdict ?? details.run.status}/></section><div className="outcome-columns"><section><h4>Evidence referenced</h4>{output?.evidence_ids.length ? output.evidence_ids.map((id) => <span key={id}><CheckCircle2 size={13}/>{shortId(id)}</span>) : <p>No evidence IDs were referenced.</p>}</section><section><h4>Known limitations</h4>{output?.limitations.length ? output.limitations.map((item) => <span key={item}><AlertTriangle size={13}/>{item}</span>) : <p>No limitations were recorded.</p>}</section></div>{evaluation ? <section className="evaluation-story"><div><small>AUTOMATED EVALUATION</small><h4>{evaluation.passed ? 'The evidence and final output passed' : 'The result needs attention'}</h4></div><div><strong>{evaluation.score == null ? '—' : `${Math.round(evaluation.score * (evaluation.score <= 1 ? 100 : 1))}%`}</strong><span>score</span></div><ul>{[...evaluation.success_reasons, ...evaluation.failure_reasons].map((reason) => <li key={reason}>{reason}</li>)}</ul></section> : null}</div>
}

function TechnicalInspector({ details }: { details: RunDetails }) {
  return <div className="technical-inspector"><div className="inspector-warning"><TerminalSquare size={18}/><div><strong>Technical data is intentionally secondary</strong><p>Use this area for debugging contracts, payloads, and stored metadata. API keys, cookies, secret values, and hidden chain-of-thought are never shown.</p></div></div><details open><summary>Events ({details.events.total})</summary><JsonViewer value={details.events.items} label="Reveal event records"/></details><details><summary>Tool results ({details.tool_results.total})</summary><JsonViewer value={details.tool_results.items} label="Reveal ToolResult records"/></details><details><summary>Model calls ({details.model_calls.total})</summary><JsonViewer value={details.model_calls.items} label="Reveal model metadata"/></details><details><summary>Recon snapshot</summary><JsonViewer value={details.recon_snapshot} label="Reveal asset graph and decisions"/></details><details><summary>Complete run record</summary><JsonViewer value={details} label="Reveal complete sanitized JSON"/></details></div>
}

function currentPhase(details: RunDetails) {
  if (!isActive(details.run.status)) return { label: humanize(details.run.status), hint: details.failure?.code ?? 'Run closed' }
  const last = details.events.items.at(-1)?.event_type
  if (last === 'model_called') return { label: 'Interpreting model decision', hint: 'Validating structured action' }
  if (last === 'tool_started') return { label: `Executing ${humanize(stringAt(details.events.items.at(-1)?.data, 'tool_name') || 'tool')}`, hint: 'Authorized local execution' }
  if (last === 'tool_completed') return { label: 'Recording observations', hint: 'Updating evidence and asset graph' }
  if (last === 'action_received') return { label: 'Checking proposed action', hint: 'Scope and policy gate' }
  return { label: 'Planning next move', hint: 'Ranking information gain' }
}

function sceneTitle(step: StepBundle) {
  if (step.events.some((event) => event.event_type === 'run_started')) return 'Mission initialized'
  if (step.events.some((event) => event.event_type === 'run_completed')) return 'Agent delivered the final answer'
  if (step.events.some((event) => event.event_type === 'run_failed')) return 'Operation stopped with an error'
  if (step.tools.length) return `${humanize(step.tools[0].tool_name)} completed`
  if (step.decision) return `Planner chose ${humanize(step.decision.mode)} mode`
  if (step.modelCalls.length) return 'Agent requested its next decision'
  return step.events.map((event) => humanize(event.event_type)).join(' · ') || 'Recorded activity'
}

function eventMessage(event: RunEvent) {
  const data = event.data ?? {}
  if (event.event_type === 'run_completed') return 'The agent submitted a final answer and evidence references.'
  if (event.event_type === 'evaluation_completed') return data.passed ? 'The automated evaluator accepted the result.' : 'The automated evaluator did not accept the result.'
  if (event.event_type === 'budget_exhausted') return `${humanize(String(data.budget ?? 'run'))} budget was exhausted.`
  return String(data.reason ?? recordAt(data, 'error')?.message ?? 'The runtime recorded this state change.')
}

function statusIcon(status: RunStatus) { return status === 'completed' ? <CheckCircle2 size={20}/> : terminalStatuses.includes(status) ? <AlertTriangle size={20}/> : <CircleDot size={20}/> }
function budgetPercent(value: number, max: number) { return max > 0 ? Math.min(100, Math.round(value / max * 100)) : 0 }
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function recordAt(value: unknown, key: string): Record<string, unknown> | undefined { return isRecord(value) && isRecord(value[key]) ? value[key] as Record<string, unknown> : undefined }
function stringAt(value: unknown, key: string): string { return isRecord(value) && typeof value[key] === 'string' ? value[key] as string : '' }
function firstValue(value: Record<string, unknown>, keys: string[]) { for (const key of keys) if (value[key] != null) return value[key]; return null }
function firstString(value: Record<string, unknown>, keys: string[]) { const found = firstValue(value, keys); return typeof found === 'string' ? found : '' }
function arrayLength(value: unknown) { return Array.isArray(value) ? value.length : 0 }
function isSecretKey(key: string) { return /key|token|cookie|authorization|secret|password|response_body/i.test(key) }
function summarize(value: unknown, max = 120) { const raw = typeof value === 'string' ? value : JSON.stringify(value); return raw.length > max ? `${raw.slice(0, max)}…` : raw }
