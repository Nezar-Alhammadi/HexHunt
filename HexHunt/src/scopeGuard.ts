export type ScopeProject = {
  targetUrl: string
  allowedDomains: string[]
  excludedDomains: string[]
  allowedPorts: number[]
  requestRate: number
  authorized: boolean
}

export type ScopeDecision = {
  allowed: boolean
  code: 'allowed' | 'invalid-url' | 'unauthorized' | 'protocol' | 'domain' | 'excluded' | 'port' | 'rate-limit'
  reason: string
}

const allow = (): ScopeDecision => ({ allowed: true, code: 'allowed', reason: 'Target is inside the authorized scope.' })

const deny = (code: ScopeDecision['code'], reason: string): ScopeDecision => ({ allowed: false, code, reason })

const normalizeHostname = (hostname: string) => hostname.toLowerCase().replace(/\.$/, '')

const normalizeRule = (rule: string) => {
  const trimmedRule = rule.trim().toLowerCase()
  const wildcard = trimmedRule.startsWith('*.')
  const rawRule = wildcard ? trimmedRule.slice(2) : trimmedRule

  try {
    const hostname = new URL(rawRule.includes('://') ? rawRule : `https://${rawRule}`).hostname
    return { hostname: normalizeHostname(hostname), wildcard }
  } catch {
    return { hostname: normalizeHostname(rawRule.split('/')[0]), wildcard }
  }
}

const matchesRule = (hostname: string, rule: string) => {
  const normalizedHostname = normalizeHostname(hostname)
  const normalizedRule = normalizeRule(rule)
  if (!normalizedRule.hostname) return false

  if (normalizedRule.wildcard) {
    return normalizedHostname.endsWith(`.${normalizedRule.hostname}`)
  }

  return normalizedHostname === normalizedRule.hostname
}

const portFor = (target: URL) => {
  if (target.port) return Number(target.port)
  return target.protocol === 'https:' ? 443 : 80
}

export const validateScopeTarget = (project: ScopeProject, targetValue: string): ScopeDecision => {
  if (!project.authorized) return deny('unauthorized', 'The project has no authorization confirmation.')

  let target: URL
  try {
    target = new URL(targetValue)
  } catch {
    return deny('invalid-url', 'The target is not a valid absolute URL.')
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return deny('protocol', 'Only HTTP and HTTPS targets are allowed.')
  }

  if (project.excludedDomains.some((rule) => matchesRule(target.hostname, rule))) {
    return deny('excluded', 'The target matches an excluded domain rule.')
  }

  if (!project.allowedDomains.some((rule) => matchesRule(target.hostname, rule))) {
    return deny('domain', 'The target is outside the allowed domains.')
  }

  if (!project.allowedPorts.includes(portFor(target))) {
    return deny('port', 'The target port is outside the allowed ports.')
  }

  return allow()
}

export class ScopeGuard {
  private requestTimes: number[] = []
  private readonly project: ScopeProject

  constructor(project: ScopeProject) {
    this.project = project
  }

  authorizeRequest(targetValue: string, now = Date.now()): ScopeDecision {
    const targetDecision = validateScopeTarget(this.project, targetValue)
    if (!targetDecision.allowed) return targetDecision

    this.requestTimes = this.requestTimes.filter((requestTime) => now - requestTime < 1000)
    if (this.requestTimes.length >= this.project.requestRate) {
      return deny('rate-limit', 'The project request rate limit has been reached.')
    }

    this.requestTimes.push(now)
    return targetDecision
  }

  authorizeRedirect(targetValue: string): ScopeDecision {
    return validateScopeTarget(this.project, targetValue)
  }
}
