import type { ReactNode } from 'react'
import { AlertCircle, ArrowRight, Inbox, LoaderCircle } from 'lucide-react'

export function PageHeader({ icon, title, description, actions }: { icon: ReactNode; title: string; description: string; actions?: ReactNode }) {
  return <header className="page-header"><div className="page-title"><span className="page-icon">{icon}</span><div><h1>{title}</h1><p>{description}</p></div></div>{actions ? <div className="page-actions">{actions}</div> : null}</header>
}

export function StatusBadge({ value, tone }: { value: string; tone?: 'success' | 'danger' | 'warning' | 'info' | 'neutral' }) {
  const inferred = tone ?? (['completed','passed','success','connected','active'].includes(value) ? 'success' : ['failed','scope_blocked','error'].includes(value) ? 'danger' : ['running','created','inconclusive','budget_exhausted'].includes(value) ? 'warning' : 'neutral')
  return <span className={`status-badge badge-${inferred}`}>{humanize(value)}</span>
}

export function MetricCard({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return <article className="metric-card"><span>{label}</span><strong>{value}</strong>{hint ? <small>{hint}</small> : null}</article>
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <div className="state-card empty-state"><Inbox size={24}/><h2>{title}</h2><p>{description}</p>{action}</div>
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return <div className="state-card"><LoaderCircle className="spinning" size={22}/><p>{label}</p></div>
}

const friendlyErrors: Record<string, string> = {
  MODEL_API_KEY_MISSING: 'OpenRouter is not configured. Add OPENROUTER_API_KEY to the environment, then restart HexHunt.',
  CONFIGURATION_ERROR: 'The model configuration is incomplete or unavailable. Check the environment configuration, then start a new Run.',
  DATABASE_READ_FAILED: 'HexHunt could not read the saved records. Check access to the application data directory.',
  DATABASE_WRITE_FAILED: 'HexHunt could not save this change. Check available disk space and permissions.',
  DATABASE_MIGRATION_FAILED: 'HexHunt could not prepare its saved-data structure. Check the application data directory and restart the application.',
  PERSISTENCE_FAILED: 'HexHunt could not read or save the research record. Check the application data directory and disk permissions.',
  AUTHENTICATIONFAILED: 'OpenRouter rejected the credentials. Replace the environment key and try again.',
  PROVIDERUNAVAILABLE: 'The model provider is temporarily unavailable. Try the run again later.',
  PROVIDER_REJECTED: 'The model provider rejected this request. Review the model configuration and provider response details.',
  PROVIDER_TIMEOUT: 'The model provider did not answer in time. Try again or use a longer timeout in a Research setup.',
  PROVIDER_CONNECTION_FAILED: 'HexHunt could not reach the model provider. Check network connectivity and the provider route.',
  INVALID_RESPONSE: 'The model response did not match the required structured action. Review the Model Call details.',
  RATELIMITED: 'The provider rate limit was reached. Wait briefly before trying again.',
}

export function ErrorState({ error, title = 'Something needs attention' }: { error: string; title?: string }) {
  const [code, ...rest] = error.split(':')
  const technical = rest.join(':').trim() || error
  const normalizedError = error.replaceAll('_', '').toUpperCase()
  const embeddedCode = Object.keys(friendlyErrors).find((key) => normalizedError.includes(key.replaceAll('_', '').toUpperCase()))
  const effectiveCode = embeddedCode ?? code.trim()
  const message = friendlyErrors[effectiveCode] ?? technical
  return <div className="error-state" role="alert"><AlertCircle size={17}/><div><strong>{title}</strong><p>{message}</p>{message !== technical ? <details><summary>Technical details</summary><code>{error}</code></details> : null}</div></div>
}

export function Tabs<T extends string>({ value, items, onChange }: { value: T; items: Array<{ value: T; label: string; count?: number }>; onChange: (value: T) => void }) {
  return <nav className="tabs" aria-label="Page sections">{items.map((item) => <button key={item.value} className={value === item.value ? 'active' : ''} onClick={() => onChange(item.value)}>{item.label}{item.count != null ? <span>{item.count}</span> : null}</button>)}</nav>
}

export function JsonViewer({ value, label = 'Show technical data' }: { value: unknown; label?: string }) {
  return <details className="technical-details"><summary>{label}</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>
}

export function RunLink({ runId, onOpen, label = 'Open run details' }: { runId: string; onOpen: (runId: string) => void; label?: string }) {
  return <button className="text-link" onClick={() => onOpen(runId)}><span>{label}</span><code>{shortId(runId)}</code><ArrowRight size={14}/></button>
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  return <button className="copy-button" onClick={() => void navigator.clipboard.writeText(value)}>{label}</button>
}

export const shortId = (value: string) => value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value
export const humanize = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
export const formatTime = (value: number) => new Date(value).toLocaleString()
export const formatDuration = (value: number) => value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`
