import { useEffect, useState } from 'react'
import { Activity, Bot, BriefcaseBusiness, Check, KeyRound, Moon, Plus, Power, RefreshCw, Settings, ShieldCheck, Sun, Users, X } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import './App.css'
import { validateScopeTarget, type ScopeProject } from './scopeGuard'
import RunsPage from './RunsPage'
import { createRun, executeAgentRun, normalizeRunError } from './api/runs'
import { EmptyState, ErrorState, MetricCard, PageHeader, StatusBadge } from './components/ui'
import type { RunMemoryMode, Task } from './types/runs'

type Theme = 'light' | 'dark'
type Page = 'start' | 'runs' | 'sessions' | 'settings'
type Project = ScopeProject & { id: string; name: string; authorized: true; createdAt: string }
type OpenRouterCredentialStatus = { configured: boolean; saved: boolean; source: 'secure_store' | 'environment' | 'none' }
type BrowserIdentity = { schema_version: number; id: string; name: string; scope_id: string; origin: string; cookie_names: string[]; header_names: string[]; created_at_ms: number }

const DEFAULT_BUG_BOUNTY_PROMPT = `Perform adaptive passive reconnaissance on the authorized target. Build and verify an Asset Graph using the available passive Recon tools. Choose each next action from the current evidence and expected information gain, avoid repeating completed observations, remain inside Scope, and finish with a concise inventory supported by stored Evidence IDs.`;

const emptyProjectForm = { name: '', targetUrl: '', allowedDomains: '', excludedDomains: '', allowedPorts: '80, 443', requestRate: 5, authorized: false }
const readProjects = (): Project[] => {
  try {
    const saved = JSON.parse(localStorage.getItem('hexhunt-projects') ?? '[]')
    return Array.isArray(saved) ? saved.map((project) => ({ ...project, allowedPorts: Array.isArray(project.allowedPorts) ? project.allowedPorts : [80, 443] })) : []
  } catch { return [] }
}
const parseDomains = (value: string) => value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
const parsePorts = (value: string) => [...new Set(value.split(/[\s,]+/).map(Number).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))]

function App() {
  const [activePage, setActivePage] = useState<Page>('start')
  const [projects, setProjects] = useState<Project[]>(readProjects)
  const [showProjectForm, setShowProjectForm] = useState(false)
  const [projectForm, setProjectForm] = useState(emptyProjectForm)
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null)
  const [activeProjectId, setActiveProjectId] = useState<string | null>(() => localStorage.getItem('hexhunt-active-project'))
  const [choosingProject, setChoosingProject] = useState(false)
  const [taskInput, setTaskInput] = useState(DEFAULT_BUG_BOUNTY_PROMPT)
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)
  const [runExecutionError, setRunExecutionError] = useState('')
  const [runLaunching, setRunLaunching] = useState(false)
  const [memoryMode, setMemoryMode] = useState<RunMemoryMode>('fresh')
  const [memorySourceRunId, setMemorySourceRunId] = useState('')
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [apiKeyStatus, setApiKeyStatus] = useState<OpenRouterCredentialStatus | null>(null)
  const [apiKeyError, setApiKeyError] = useState('')
  const [apiKeyLoading, setApiKeyLoading] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('hexhunt-theme')
    return saved === 'light' || saved === 'dark' ? saved : window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  useEffect(() => { localStorage.setItem('hexhunt-theme', theme) }, [theme])
  useEffect(() => { localStorage.setItem('hexhunt-projects', JSON.stringify(projects)) }, [projects])
  useEffect(() => { if (activeProjectId) localStorage.setItem('hexhunt-active-project', activeProjectId); else localStorage.removeItem('hexhunt-active-project') }, [activeProjectId])
  useEffect(() => {
    if (!('__TAURI_INTERNALS__' in window)) return
    void invoke<OpenRouterCredentialStatus>('openrouter_api_key_status')
      .then(setApiKeyStatus)
      .catch((cause) => setApiKeyError(cause instanceof Error ? cause.message : String(cause)))
  }, [])

  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? null
  const activeProject = projects.find((project) => project.id === activeProjectId) ?? null
  const selectedScopeDecision = selectedProject ? validateScopeTarget(selectedProject, selectedProject.targetUrl) : null

  const createProject = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!projectForm.authorized) return
    const project: Project = { id: crypto.randomUUID(), name: projectForm.name.trim(), targetUrl: projectForm.targetUrl.trim(), allowedDomains: parseDomains(projectForm.allowedDomains), excludedDomains: parseDomains(projectForm.excludedDomains), allowedPorts: parsePorts(projectForm.allowedPorts), requestRate: projectForm.requestRate, authorized: true, createdAt: new Date().toISOString() }
    setProjects((current) => [project, ...current]); setProjectForm(emptyProjectForm); setShowProjectForm(false)
    if (validateScopeTarget(project, project.targetUrl).allowed) {
      setActiveProjectId(project.id); setSelectedProjectId(null); setChoosingProject(false)
    } else {
      setSelectedProjectId(project.id); setChoosingProject(true)
    }
  }
  const activateProject = () => {
    if (!selectedProject || !selectedScopeDecision?.allowed) return
    setActiveProjectId(selectedProject.id); setSelectedProjectId(null); setChoosingProject(false); setActivePage('start')
  }
  const launchAgentRun = async () => {
    if (!activeProject || !taskInput.trim() || !('__TAURI_INTERNALS__' in window)) {
      if (!('__TAURI_INTERNALS__' in window)) setRunExecutionError('DESKTOP_RUNTIME_REQUIRED: Agent runs require the HexHunt desktop application.')
      return
    }
    if (memoryMode === 'continue' && !memorySourceRunId.trim()) {
      setRunExecutionError('SOURCE_RUN_REQUIRED: Choose a source Run ID or use Fresh run.')
      return
    }
    setRunLaunching(true); setRunExecutionError('')
    const task: Task = {
      schema_version: 1, id: '', objective: taskInput.trim(), primary_target: activeProject.targetUrl,
      scope: { id: activeProject.id, allowed_domains: activeProject.allowedDomains, excluded_domains: activeProject.excludedDomains, allowed_ports: activeProject.allowedPorts, request_rate: activeProject.requestRate, authorized: true },
      budget: { max_steps: 0, max_http_requests: 0, max_model_calls: 0, max_input_tokens: 0, max_output_tokens: 0, max_duration_ms: 0 },
      available_tools: ['search_certificate_transparency', 'lookup_web_archive', 'resolve_dns', 'inspect_dns_ownership', 'inspect_rdap', 'probe_tcp_service', 'probe_http', 'validate_url_metadata', 'discover_content', 'fetch_robots_txt', 'fetch_sitemap', 'analyze_web_page', 'adaptive_browser_recon', 'analyze_javascript', 'describe_api', 'analyze_visual_page', 'query_external_intelligence'],
      memory_policy: {
        mode: memoryMode,
        source_run_ids: memoryMode === 'continue' && memorySourceRunId.trim() ? [memorySourceRunId.trim()] : [],
        max_age_ms: memoryMode === 'auto_assisted' ? 7 * 24 * 60 * 60 * 1000 : null,
        max_source_runs: memoryMode === 'auto_assisted' ? 5 : 1,
      },
    }
    try {
      const run = await createRun(task)
      setSelectedRunId(run.id); setTaskInput(DEFAULT_BUG_BOUNTY_PROMPT); setMemoryMode('fresh'); setMemorySourceRunId(''); setActivePage('runs')
      void executeAgentRun(run.id).catch((cause) => { const error = normalizeRunError(cause); setRunExecutionError(`${error.code}: ${error.message}`) }).finally(() => setRunLaunching(false))
    } catch (cause) {
      const error = normalizeRunError(cause); setRunExecutionError(`${error.code}: ${error.message}`); setRunLaunching(false)
    }
  }
  const saveApiKey = async () => {
    if (!apiKeyInput.trim()) return
    setApiKeyLoading(true); setApiKeyError('')
    try {
      setApiKeyStatus(await invoke<OpenRouterCredentialStatus>('save_openrouter_api_key', { apiKey: apiKeyInput }))
      setApiKeyInput('')
    } catch (cause) {
      setApiKeyError(cause instanceof Error ? cause.message : String(cause))
    } finally { setApiKeyLoading(false) }
  }
  const deleteApiKey = async () => {
    setApiKeyLoading(true); setApiKeyError('')
    try {
      setApiKeyStatus(await invoke<OpenRouterCredentialStatus>('delete_openrouter_api_key'))
      setApiKeyInput('')
    } catch (cause) {
      setApiKeyError(cause instanceof Error ? cause.message : String(cause))
    } finally { setApiKeyLoading(false) }
  }

  const navigate = (page: Page) => {
    setActivePage(page)
  }

  return <main className={`app-shell theme-${theme}`}>
    <header className="topbar">
      <div className="topbar-brand"><span className="brand-mark">H</span><div><strong>HexHunt</strong><small>Security agent</small></div></div>
      <nav className="topbar-nav" aria-label="Main navigation">{([
        ['start','New run',Bot], ['runs','Runs & results',Activity], ['sessions','Sessions',Users], ['settings','Settings',Settings],
      ] as const).map(([page,label,Icon]) => <button key={page} className={activePage === page ? 'active' : ''} onClick={() => navigate(page)}><Icon size={16}/><span>{label}</span></button>)}</nav>
      <div className="topbar-context"><div className="topbar-target"><small>Authorized target</small><strong>{activeProject?.name ?? 'No target selected'}</strong><span>{activeProject?.targetUrl ?? 'Choose a target from New run'}</span></div><StatusBadge value={activeProject ? 'ready' : 'setup'} tone={activeProject ? 'success' : 'neutral'}/></div>
    </header>

    <section className="shell-main">
      <header className="shell-header"><div><span>Authorized target</span><strong>{activeProject ? `${activeProject.name} · ${activeProject.targetUrl}` : 'Choose a target from New run'}</strong></div><div className="shell-model"><span>Runtime</span><strong>HexHunt Core</strong><StatusBadge value="ready" tone="success"/></div></header>
      <div className="page-content">
        {activePage === 'start' ? <div className="start-run-page"><RunSetupSteps targetReady={Boolean(activeProject) && !choosingProject} memoryMode={memoryMode} setMemoryMode={setMemoryMode} sourceRunId={memorySourceRunId} setSourceRunId={setMemorySourceRunId}/>{!activeProject || choosingProject ? <ProjectsPage projects={projects} selected={selectedProject} activeProjectId={activeProjectId} showForm={showProjectForm} setShowForm={setShowProjectForm} setSelectedId={setSelectedProjectId} form={projectForm} setForm={setProjectForm} createProject={createProject} decision={selectedScopeDecision} activate={activateProject}/> : <AgentPage project={activeProject} taskInput={taskInput} launch={launchAgentRun} launching={runLaunching} error={runExecutionError} openProjects={() => { setSelectedProjectId(null); setShowProjectForm(false); setChoosingProject(true) }}/>}</div> : null}
        {activePage === 'runs' ? <RunsPage selectedRunId={selectedRunId} onSelectRun={setSelectedRunId} executionError={runExecutionError}/> : null}
        {activePage === 'sessions' ? <SessionsPage project={activeProject}/> : null}
        {activePage === 'settings' ? <SettingsPage theme={theme} setTheme={setTheme} apiKey={apiKeyInput} setApiKey={setApiKeyInput} apiKeyStatus={apiKeyStatus} apiKeyError={apiKeyError} apiKeyLoading={apiKeyLoading} saveApiKey={saveApiKey} deleteApiKey={deleteApiKey}/> : null}
      </div>
    </section>
  </main>
}

function RunSetupSteps({ targetReady, memoryMode, setMemoryMode, sourceRunId, setSourceRunId }: { targetReady: boolean; memoryMode: RunMemoryMode; setMemoryMode: (mode: RunMemoryMode) => void; sourceRunId: string; setSourceRunId: (id: string) => void }) {
  return <div className="run-setup-header"><ol className="run-setup-steps" aria-label="Run setup progress">
    <li className={targetReady ? 'complete' : 'active'}><span>1</span><div><strong>Target & scope</strong><small>{targetReady ? 'Authorized target selected' : 'Choose where HexHunt may test'}</small></div></li>
    <li className={targetReady ? 'active' : 'locked'}><span>2</span><div><strong>Task</strong><small>{targetReady ? 'Describe what you want checked' : 'Available after choosing a target'}</small></div></li>
    <li className="locked"><span>3</span><div><strong>Results</strong><small>Opens automatically after starting</small></div></li>
  </ol><section className="run-memory-control" aria-label="Run memory"><div><strong>Previous-run memory</strong><small>Old results are clues only; HexHunt revalidates them before using them as evidence.</small></div><label><span>Mode</span><select value={memoryMode} onChange={(event) => setMemoryMode(event.target.value as RunMemoryMode)}><option value="fresh">Fresh run (recommended)</option><option value="continue">Continue a specific run</option><option value="auto_assisted">Auto-assisted (last 7 days)</option></select></label>{memoryMode === 'continue' ? <label><span>Source Run ID</span><input required value={sourceRunId} onChange={(event) => setSourceRunId(event.target.value)} placeholder="Paste the Run ID to continue"/></label> : null}</section></div>
}

function ProjectsPage({ projects, selected, activeProjectId, showForm, setShowForm, setSelectedId, form, setForm, createProject, decision, activate }: { projects: Project[]; selected: Project | null; activeProjectId: string | null; showForm: boolean; setShowForm: (value:boolean)=>void; setSelectedId:(value:string|null)=>void; form: typeof emptyProjectForm; setForm: React.Dispatch<React.SetStateAction<typeof emptyProjectForm>>; createProject:(event:React.FormEvent<HTMLFormElement>)=>void; decision: ReturnType<typeof validateScopeTarget> | null; activate:()=>void }) {
  return <div className="projects-page"><PageHeader icon={<BriefcaseBusiness size={19}/>} title="1. Choose target & scope" description="Select an authorized website or add a new one. This defines where HexHunt is allowed to operate." actions={projects.length > 0 && !showForm ? <button className="button primary" onClick={() => { setSelectedId(null); setShowForm(true) }}><Plus size={14}/>Add target</button> : undefined}/>
    {showForm ? <form className="panel project-form" onSubmit={createProject}><div className="panel-heading"><div><h2>Add an authorized target</h2><p>Set the boundaries once. HexHunt applies them automatically to every run.</p></div><button className="icon-button" type="button" onClick={() => setShowForm(false)} aria-label="Close form"><X size={17}/></button></div><div className="form-grid"><label><span>Display name</span><input required value={form.name} onChange={(event)=>setForm({...form,name:event.target.value})} placeholder="Example: Acme staging"/></label><label><span>Target URL</span><input required type="url" value={form.targetUrl} onChange={(event)=>setForm({...form,targetUrl:event.target.value})} placeholder="https://staging.example.com"/></label><label><span>Allowed domains</span><textarea required value={form.allowedDomains} onChange={(event)=>setForm({...form,allowedDomains:event.target.value})} placeholder={'staging.example.com\napi.staging.example.com'}/></label><label><span>Excluded domains (optional)</span><textarea value={form.excludedDomains} onChange={(event)=>setForm({...form,excludedDomains:event.target.value})} placeholder="accounts.example.com"/></label><label><span>Allowed ports</span><input required value={form.allowedPorts} onChange={(event)=>setForm({...form,allowedPorts:event.target.value})}/></label><label><span>Maximum requests / second</span><input required type="number" min="1" max="100" value={form.requestRate} onChange={(event)=>setForm({...form,requestRate:Number(event.target.value)})}/></label></div><label className="authorization-check"><input type="checkbox" checked={form.authorized} onChange={(event)=>setForm({...form,authorized:event.target.checked})}/><ShieldCheck size={17}/><span>I confirm that I am authorized to test this target.</span></label><div className="form-footer"><p>After saving, you will continue directly to the task.</p><button className="button primary" disabled={!form.authorized}><Check size={14}/>Save target & continue</button></div></form> : selected ? <ProjectDetail project={selected} active={selected.id === activeProjectId} decision={decision} activate={activate} back={() => setSelectedId(null)}/> : projects.length ? <section className="panel"><div className="panel-heading"><div><h2>Choose a saved target</h2><p>Your selection becomes the boundary for the next run.</p></div></div><div className="project-table">{projects.map((project)=><button key={project.id} onClick={()=>setSelectedId(project.id)}><div><strong>{project.name}</strong><span>{project.targetUrl}</span></div><StatusBadge value={project.id === activeProjectId ? 'current' : 'authorized'} tone={project.id === activeProjectId ? 'success':'info'}/><span>{project.allowedDomains.length} domains</span><span>{project.requestRate} req/s</span></button>)}</div></section> : <EmptyState title="Add your first authorized target" description="Enter the website and its allowed boundaries. Then HexHunt will take you directly to writing the task." action={<button className="button primary" onClick={()=>setShowForm(true)}><Plus size={14}/>Add target</button>}/>}</div>
}

function ProjectDetail({ project, active, decision, activate, back }: { project:Project; active:boolean; decision:ReturnType<typeof validateScopeTarget>|null; activate:()=>void; back:()=>void }) {
  return <div className="project-detail-view"><button className="context-return" onClick={back}>← Back to targets</button>{!decision?.allowed ? <ErrorState error={`SCOPE_INVALID: ${decision?.reason ?? 'The target URL is outside the allowed domains.'}`}/> : null}<section className={`decision-card ${decision?.allowed ? 'success' : 'danger'}`}><div><span>Authorization check</span><h3>{decision?.allowed ? 'This target is ready to use' : 'Fix the scope before continuing'}</h3><p>{project.targetUrl}</p></div><div><StatusBadge value={active ? 'current' : 'authorized'} tone={active?'success':'info'}/><button className="button primary" disabled={!decision?.allowed} onClick={activate}>{active ? <Check size={14}/> : <Power size={14}/>}{active ? 'Continue with this target' : 'Use this target'}</button></div></section><div className="metric-grid"><MetricCard label="Allowed domains" value={project.allowedDomains.length}/><MetricCard label="Excluded domains" value={project.excludedDomains.length}/><MetricCard label="Allowed ports" value={project.allowedPorts.join(', ')}/><MetricCard label="Request rate" value={`${project.requestRate}/s`}/></div><details className="advanced-section"><summary>Review scope details</summary><section className="scope-panel"><dl><dt>Target</dt><dd>{project.targetUrl}</dd><dt>Allowed</dt><dd>{project.allowedDomains.join(', ')}</dd><dt>Excluded</dt><dd>{project.excludedDomains.join(', ') || 'None'}</dd><dt>Ports</dt><dd>{project.allowedPorts.join(', ')}</dd></dl></section></details></div>
}

function AgentPage({ project, taskInput, launch, launching, error, openProjects }: { project:Project; taskInput:string; launch:()=>void; launching:boolean; error:string; openProjects:()=>void }) {
  return <div className="agent-page"><PageHeader icon={<Bot size={19}/>} title="2. Agentic Bug Bounty" description="The target is ready. HexHunt will perform a comprehensive security assessment using agentic execution." actions={<button className="button secondary" onClick={openProjects}>Change target</button>}/><div className="agent-layout"><section className="agentic-launch-area" style={{alignSelf: 'start', display: 'flex', flexDirection: 'column', gap: '24px', padding: '16px 0'}}><button className="button primary" style={{height: '56px', fontSize: '15px', borderRadius: '12px', justifyContent: 'center', padding: '0 32px', width: 'max-content', boxShadow: '0 8px 24px rgba(239, 62, 67, 0.25)'}} disabled={launching || !taskInput.trim()} onClick={launch}>{launching ? <RefreshCw className="spinning" size={18}/> : <Activity size={18}/>}{launching ? 'Initializing Agents…' : 'Start Agentic Hunt'}</button>{error ? <ErrorState error={error}/> : null}</section><aside className="agent-context"><section className="panel selected-target-card"><div className="selected-target-heading"><ShieldCheck size={17}/><div><span>Selected target</span><strong>{project.name}</strong></div></div><p className="wrap-value">{project.targetUrl}</p><dl><dt>Allowed domains</dt><dd>{project.allowedDomains.length}</dd><dt>Ports</dt><dd>{project.allowedPorts.join(', ')}</dd><dt>Rate limit</dt><dd>{project.requestRate}/s</dd></dl></section><section className="panel next-steps-card"><h3>What happens next?</h3><ol><li>HexHunt stays inside this authorized scope.</li><li>The run opens automatically.</li><li>The final answer and evidence appear together.</li></ol></section></aside></div></div>
}

function SessionsPage({ project }: { project: Project | null }) {
  const [identities, setIdentities] = useState<BrowserIdentity[]>([])
  const [name, setName] = useState('')
  const [cookies, setCookies] = useState('')
  const [authorization, setAuthorization] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const refresh = async () => setIdentities(await invoke<BrowserIdentity[]>('list_browser_identities'))
  useEffect(() => { if ('__TAURI_INTERNALS__' in window) void refresh().catch(() => undefined) }, [project?.id])

  const save = async () => {
    if (!project || !name.trim()) return
    setLoading(true); setError('')
    try {
      const origin = new URL(project.targetUrl).origin
      const parsedCookies = cookies.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
        const separator = line.indexOf('=')
        if (separator < 1) throw new Error('IDENTITY_INVALID_COOKIE: use one name=value cookie per line.')
        return { name: line.slice(0, separator).trim(), value: line.slice(separator + 1), domain: null, path: '/', secure: origin.startsWith('https://'), http_only: false }
      })
      const headers = authorization.trim() ? { Authorization: authorization.trim() } : {}
      await invoke('save_browser_identity', { identity: { id: null, name: name.trim(), scope_id: project.id, origin, cookies: parsedCookies, headers } })
      await refresh(); setName(''); setCookies(''); setAuthorization('')
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)) }
    finally { setLoading(false) }
  }
  const remove = async (identityId: string) => {
    setLoading(true); setError('')
    try { await invoke('delete_browser_identity', { identityId }); await refresh() }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)) }
    finally { setLoading(false) }
  }

  const scoped = identities.filter((identity) => identity.scope_id === project?.id)
  return <div className="settings-page"><PageHeader icon={<Users size={19}/>} title="Sessions & identities" description="Give Adaptive Browser Recon authorized account views to compare for the current target."/>{!project ? <EmptyState title="Choose a target first" description="Open New run and select the authorized target these sessions belong to."/> : <div className="settings-grid"><section className="panel settings-card"><h2>Add an identity</h2><p>Secrets remain only in memory until HexHunt closes and are never written into Run results.</p>{error ? <ErrorState error={error}/> : null}<label><span>Identity name</span><input value={name} onChange={(event)=>setName(event.target.value)} placeholder="Example: standard user"/></label><label><span>Cookies · one name=value per line</span><textarea spellCheck={false} value={cookies} onChange={(event)=>setCookies(event.target.value)} placeholder={'session=…\ncsrf=…'}/></label><label><span>Authorization header (optional)</span><input type="password" autoComplete="off" spellCheck={false} value={authorization} onChange={(event)=>setAuthorization(event.target.value)} placeholder="Bearer …"/></label><button className="button primary" disabled={loading || !name.trim()} onClick={save}>{loading ? <RefreshCw className="spinning" size={14}/> : <Plus size={14}/>}Add identity</button></section><section className="panel settings-card"><h2>Available for {project.name}</h2><p>The Agent can select up to four identities and compare page and network metadata.</p>{scoped.length ? scoped.map((identity)=><div className="connection-summary" key={identity.id}><StatusBadge value="ready" tone="success"/><strong>{identity.name}</strong><span>{identity.cookie_names.length} cookies · {identity.header_names.length} headers</span><button className="button secondary danger-text" disabled={loading} onClick={()=>remove(identity.id)}>Remove</button></div>) : <p>No identities yet. Anonymous browsing remains available.</p>}</section></div>}</div>
}

function SettingsPage({ theme, setTheme, apiKey, setApiKey, apiKeyStatus, apiKeyError, apiKeyLoading, saveApiKey, deleteApiKey }: { theme:Theme; setTheme:(theme:Theme)=>void; apiKey:string; setApiKey:(value:string)=>void; apiKeyStatus:OpenRouterCredentialStatus|null; apiKeyError:string; apiKeyLoading:boolean; saveApiKey:()=>void; deleteApiKey:()=>void }) {
  return <div className="settings-page"><PageHeader icon={<Settings size={19}/>} title="Settings" description="Manage the model connection and application appearance."/><div className="settings-grid"><section className="panel settings-card"><h2>Appearance</h2><p>Choose the interface theme for this device.</p><div className="segmented"><button className={theme==='light'?'active':''} onClick={()=>setTheme('light')}><Sun size={14}/>Light</button><button className={theme==='dark'?'active':''} onClick={()=>setTheme('dark')}><Moon size={14}/>Dark</button></div></section><section className="panel settings-card openrouter-card"><h2>OpenRouter connection</h2><p>Save the key once. HexHunt stores it in the operating system secret store and loads it automatically.</p>{apiKeyError ? <ErrorState error={apiKeyError}/> : null}<div className="connection-summary"><StatusBadge value={apiKeyStatus?.configured ? 'connected' : 'not configured'} tone={apiKeyStatus?.configured ? 'success' : 'warning'}/><strong>{apiKeyStatus?.configured ? 'API key ready' : 'API key required'}</strong><span>{apiKeyStatus?.saved ? 'Saved securely on this device' : apiKeyStatus?.source === 'environment' ? 'Available for this session only' : 'Enter a key below'}</span></div><label><span>OpenRouter API key</span><div className="secret-input"><KeyRound size={15}/><input type="password" autoComplete="off" spellCheck={false} value={apiKey} onChange={(event)=>setApiKey(event.target.value)} placeholder={apiKeyStatus?.configured ? 'Enter a new key to replace the saved key' : 'sk-or-v1-…'}/></div></label><div className="credential-actions"><button className="button primary" disabled={apiKeyLoading || !apiKey.trim()} onClick={saveApiKey}>{apiKeyLoading ? <RefreshCw className="spinning" size={14}/> : <KeyRound size={14}/>}Save securely</button>{apiKeyStatus?.configured ? <button className="button secondary danger-text" disabled={apiKeyLoading} onClick={deleteApiKey}>Remove key</button> : null}</div><details className="advanced-section"><summary>Model details</summary><dl><dt>Provider</dt><dd>OpenRouter</dd><dt>Default model</dt><dd>deepseek/deepseek-v4-flash</dd><dt>Storage</dt><dd>Operating system secret store</dd></dl></details></section></div></div>
}

export default App
