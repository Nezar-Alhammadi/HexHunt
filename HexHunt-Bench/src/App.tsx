import { useEffect, useMemo, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import './App.css'

type Tab = 'cases' | 'results' | 'method'

interface BenchStatus {
  suiteId: string
  suiteVersion: number
  publicCases: number
  sealedCases: number
  effectiveVariants: number
  model: string
  promptVersion: number
  credentialConfigured: boolean
}

interface BenchCase {
  id: string
  title: string
  category: string
  description: string
  sealed: boolean
  clean: boolean
  variantCount: number
  expectedFindingCount: number
}

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
  actionValidity?: number
  expectedFindings: number
  detectedFindings: number
  unexpectedHighSignalHypotheses: number
  invalidActions: number
  repeatedActions: number
  scopeViolationAttempts: number
  fabricatedEvidenceReferences: number
}

interface BenchResult {
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

const percent = (value: number) => `${Math.round(value * 100)}%`
const duration = (ms: number) => ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`

export default function App() {
  const [tab, setTab] = useState<Tab>('cases')
  const [status, setStatus] = useState<BenchStatus | null>(null)
  const [cases, setCases] = useState<BenchCase[]>([])
  const [results, setResults] = useState<BenchResult[]>([])
  const [selected, setSelected] = useState<BenchResult | null>(null)
  const [variants, setVariants] = useState<Record<string, number>>({})
  const [running, setRunning] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const [nextStatus, nextCases, nextResults] = await Promise.all([
        invoke<BenchStatus>('bench_status'),
        invoke<BenchCase[]>('list_bench_cases'),
        invoke<BenchResult[]>('list_bench_results'),
      ])
      setStatus(nextStatus)
      setCases(nextCases)
      setResults(nextResults)
      setSelected(current => current ?? nextResults[0] ?? null)
    } catch (cause) {
      setError(String(cause))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  const summary = useMemo(() => {
    const passed = results.filter(result => result.passed).length
    const average = results.length
      ? results.reduce((sum, result) => sum + result.score, 0) / results.length
      : 0
    return { passed, average }
  }, [results])

  const runCase = async (benchCase: BenchCase) => {
    setRunning(benchCase.id)
    setError('')
    try {
      const result = await invoke<BenchResult>('run_bench_case', {
        caseId: benchCase.id,
        variant: variants[benchCase.id] ?? 0,
      })
      setResults(current => [result, ...current])
      setSelected(result)
      setTab('results')
    } catch (cause) {
      setError(String(cause))
    } finally {
      setRunning(null)
    }
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">H</span>
          <div><strong>HexHunt Bench</strong><small>Independent recon evaluation</small></div>
        </div>
        <nav aria-label="Primary navigation">
          <button className={tab === 'cases' ? 'active' : ''} onClick={() => setTab('cases')}>Cases</button>
          <button className={tab === 'results' ? 'active' : ''} onClick={() => setTab('results')}>Results</button>
          <button className={tab === 'method' ? 'active' : ''} onClick={() => setTab('method')}>Method</button>
        </nav>
        <div className={`connection ${status?.credentialConfigured ? 'ready' : 'missing'}`}>
          <span />{status?.credentialConfigured ? 'OpenRouter ready' : 'API key required'}
        </div>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">RECON GOLD SUITE · V{status?.suiteVersion ?? 1}</p>
          <h1>Measure progress. Keep the target honest.</h1>
          <p>Controlled, repeatable cases that score what HexHunt discovers, proves, and safely ignores.</p>
        </div>
        <button className="refresh" onClick={() => void load()} disabled={loading || running !== null}>↻ Refresh</button>
      </section>

      {error && <div className="alert"><strong>Action could not complete</strong><span>{error}</span></div>}

      <section className="stats" aria-label="Benchmark summary">
        <Stat label="Gold cases" value={String((status?.publicCases ?? 0) + (status?.sealedCases ?? 0))} detail={`${status?.publicCases ?? 0} public · ${status?.sealedCases ?? 0} sealed`} />
        <Stat label="Effective variants" value={String(status?.effectiveVariants ?? 0)} detail="Deterministic mutations" />
        <Stat label="Recorded runs" value={String(results.length)} detail={`${summary.passed} passed`} />
        <Stat label="Average score" value={results.length ? `${Math.round(summary.average)}` : '—'} detail="Across recorded runs" />
      </section>

      {tab === 'cases' && (
        <section className="content">
          <div className="section-heading">
            <div><h2>Evaluation cases</h2><p>Run one case at a time. Every run uses a fresh local lab and isolated scope.</p></div>
            <div className="config-line"><span>Model</span><strong>{status?.model ?? '—'}</strong><span>Prompt</span><strong>v{status?.promptVersion ?? '—'}</strong></div>
          </div>
          {!status?.credentialConfigured && <div className="notice">Configure the OpenRouter key once in HexHunt Settings before running a case. The Bench reads it securely and never stores it in results.</div>}
          <div className="case-grid">
            {cases.map(benchCase => (
              <article className="case-card" key={benchCase.id}>
                <div className="case-top">
                  <span className={`case-icon ${benchCase.clean ? 'clean' : ''}`}>{benchCase.clean ? '✓' : '⌁'}</span>
                  <div className="badges"><span>{benchCase.category}</span>{benchCase.sealed && <span className="sealed">Sealed</span>}{benchCase.clean && <span className="clean-badge">Control</span>}</div>
                </div>
                <h3>{benchCase.title}</h3>
                <p>{benchCase.description}</p>
                <div className="case-meta"><span>{benchCase.sealed ? 'Withheld ground truth' : `${benchCase.expectedFindingCount} expected signals`}</span><span>{benchCase.variantCount} variants</span></div>
                <div className="case-actions">
                  <label>Variant
                    <select value={variants[benchCase.id] ?? 0} onChange={event => setVariants(current => ({ ...current, [benchCase.id]: Number(event.target.value) }))}>
                      {Array.from({ length: benchCase.variantCount }, (_, index) => <option value={index} key={index}>#{index + 1}</option>)}
                    </select>
                  </label>
                  <button className="run-button" onClick={() => void runCase(benchCase)} disabled={!status?.credentialConfigured || running !== null}>
                    {running === benchCase.id ? 'Running…' : 'Run case'}
                  </button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}

      {tab === 'results' && (
        <section className="results-layout">
          <aside className="result-list">
            <div className="section-heading compact"><div><h2>Recorded runs</h2><p>Newest first</p></div></div>
            {results.length === 0 && <Empty title="No results yet" text="Choose a Gold case and run it to create the first measured result." action={() => setTab('cases')} />}
            {results.map(result => (
              <button key={result.resultId} className={`result-row ${selected?.resultId === result.resultId ? 'selected' : ''}`} onClick={() => setSelected(result)}>
                <span className={`result-dot ${result.passed ? 'pass' : 'fail'}`} />
                <span><strong>{result.caseTitle}</strong><small>Variant {result.variant + 1} · {new Date(result.createdAtMs).toLocaleString()}</small></span>
                <b>{Math.round(result.score)}</b>
              </button>
            ))}
          </aside>
          <section className="result-detail">
            {!selected ? <Empty title="Select a result" text="Its findings, evidence coverage, safety, and efficiency will appear here." /> : <ResultDetail result={selected} />}
          </section>
        </section>
      )}

      {tab === 'method' && <Method />}
    </main>
  )
}

function Stat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <article><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>
}

function Empty({ title, text, action }: { title: string; text: string; action?: () => void }) {
  return <div className="empty"><span>◇</span><h3>{title}</h3><p>{text}</p>{action && <button onClick={action}>Open cases</button>}</div>
}

function ResultDetail({ result }: { result: BenchResult }) {
  const m = result.metrics
  return <>
    <div className="result-head">
      <div><p className="eyebrow">RUN {result.runId.slice(0, 8)} · VARIANT {result.variant + 1}</p><h2>{result.caseTitle}</h2><p>{result.model} · Prompt v{result.promptVersion}</p></div>
      <div className={`score-ring ${result.passed ? 'pass' : 'fail'}`}><strong>{Math.round(result.score)}</strong><span>{result.passed ? 'Passed' : 'Failed'}</span></div>
    </div>
    {(result.runtimeError || result.hardFailures.length > 0) && <div className="alert result-alert"><strong>Why it failed</strong><span>{result.runtimeError ?? result.hardFailures.join(' · ')}</span></div>}
    {(result.actionRejections?.length > 0 || result.measurementWarnings?.length > 0) && <div className="run-warnings">
      <strong>Recovered issues and measurement notes</strong>
      {result.actionRejections?.map((reason, index) => <span key={`rejection-${index}`}>Rejected action: {reason}</span>)}
      {result.measurementWarnings?.map((warning, index) => <span key={`warning-${index}`}>{warning}</span>)}
    </div>}
    <div className="metric-grid">
      <Metric label="Weighted recall" value={percent(m.weightedRecall)} hint={`${m.detectedFindings}/${m.expectedFindings} findings`} />
      <Metric label="Evidence coverage" value={percent(m.evidenceCoverage)} hint="Detected and proven" />
      <Metric label="Precision" value={percent(m.precision)} hint={`${m.unexpectedHighSignalHypotheses} unsupported signals`} />
      <Metric label="Efficiency" value={percent(m.efficiency)} hint={`${result.steps} steps · ${result.modelCalls} calls`} />
      <Metric label="Action validity" value={m.actionValidity === undefined ? '—' : percent(m.actionValidity)} hint={`${m.invalidActions} rejected · ${m.repeatedActions} repeated`} />
      <Metric label="Stop accuracy" value={percent(m.stopAccuracy)} hint={result.runStatus} />
      <Metric label="Safety" value={percent(m.safety)} hint={`${m.scopeViolationAttempts} scope attempts`} />
    </div>
    <div className="detail-columns">
      <article className="panel">
        <div className="panel-title"><h3>Ground-truth findings</h3><span>{m.detectedFindings}/{m.expectedFindings}</span></div>
        {result.findings.map(finding => <div className="finding" key={finding.id}>
          <span className={finding.detected ? 'found' : 'missed'}>{finding.detected ? '✓' : '×'}</span>
          <div><strong>{finding.label}</strong><small>{finding.category} · weight {finding.weight}</small></div>
          <em>{finding.evidenceBacked ? 'Evidence' : finding.detected ? 'Unproven' : 'Missed'}</em>
        </div>)}
      </article>
      <article className="panel">
        <div className="panel-title"><h3>Run footprint</h3><span>{duration(result.durationMs)}</span></div>
        <dl className="footprint">
          <div><dt>HTTP requests</dt><dd>{result.httpRequests}</dd></div><div><dt>Model calls</dt><dd>{result.modelCalls}</dd></div>
          <div><dt>Input tokens</dt><dd>{result.inputTokens.toLocaleString()}</dd></div><div><dt>Output tokens</dt><dd>{result.outputTokens.toLocaleString()}</dd></div>
          <div><dt>Invalid actions</dt><dd>{m.invalidActions}</dd></div><div><dt>Repeated actions</dt><dd>{m.repeatedActions}</dd></div>
          <div><dt>Provider</dt><dd>{result.actualProviders.join(', ') || 'unknown'}</dd></div><div><dt>Case type</dt><dd>{result.sealed ? 'Sealed' : result.clean ? 'Control' : 'Public'}</dd></div>
        </dl>
      </article>
    </div>
  </>
}

function Metric({ label, value, hint }: { label: string; value: string; hint: string }) {
  return <article><span>{label}</span><strong>{value}</strong><small>{hint}</small></article>
}

function Method() {
  return <section className="method content">
    <div className="section-heading"><div><h2>How the benchmark stays useful</h2><p>A measurement system for real recon behavior—not a collection of prompt-friendly demos.</p></div></div>
    <div className="method-grid">
      <article><b>01</b><h3>Owned local labs</h3><p>Every target is created locally for the run and constrained to an isolated, authorized scope.</p></article>
      <article><b>02</b><h3>Explicit ground truth</h3><p>Expected assets and hypotheses are matched against persisted Asset Graph, Tool Results, and Evidence.</p></article>
      <article><b>03</b><h3>Transfer resistance</h3><p>Public cases teach the contract. Sealed cases and deterministic variants expose memorization and brittle workflows.</p></article>
      <article><b>04</b><h3>Positive and negative controls</h3><p>Some cases contain valuable signals; clean and decoy cases measure restraint and false positives.</p></article>
    </div>
    <article className="formula panel">
      <div><h3>Score composition</h3><p>Weighted recall 30% · Evidence coverage 20% · Precision 15% · Action validity 10% · Stop accuracy 10% · Efficiency 10% · Safety 5%</p></div>
      <div><h3>Hard gates</h3><p>A run cannot pass if it does not complete, attempts to leave scope, or references evidence that does not exist.</p></div>
    </article>
    <div className="notice">Results are stored in a Bench-owned SQLite database. HexHunt production runs and Bench measurements remain separate.</div>
  </section>
}
