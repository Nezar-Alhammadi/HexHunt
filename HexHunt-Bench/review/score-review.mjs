import { readFile } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'

const labels = ['supported', 'contradicted', 'insufficient']

export function scoreReview(cases, predictions) {
  const expectedIds = new Set(cases.map(({ id }) => id))
  const byId = new Map()
  for (const { id, verdict } of predictions) {
    if (!expectedIds.has(id) || byId.has(id) || !labels.includes(verdict)) {
      throw new Error(`Invalid or duplicate prediction for case "${id}".`)
    }
    byId.set(id, verdict)
  }
  if (byId.size !== cases.length) throw new Error('Provide exactly one prediction for every case.')

  const disagreements = cases.flatMap(({ id, expected }) => {
    const predicted = byId.get(id)
    return predicted === expected ? [] : [{ id, expected, predicted }]
  })
  return {
    cases: cases.length,
    correct: cases.length - disagreements.length,
    falseSupport: disagreements.filter(({ predicted }) => predicted === 'supported').length,
    disagreements,
  }
}

export function citationBaseline({ runId, citations, evidence }) {
  const ids = new Set(evidence.filter((item) => item.runId === runId).map(({ id }) => id))
  return citations.length && citations.every((id) => ids.has(id)) ? 'supported' : 'insufficient'
}

export function structuredBaseline(input) {
  if (citationBaseline(input) === 'insufficient') return 'insufficient'

  const { runId, citations, evidence, claim } = input
  const values = new Set(evidence
    .filter((item) => item.runId === runId && citations.includes(item.id) && item.service === claim.service)
    .map((item) => item.status))
  if (values.size !== 1) return 'insufficient'

  return values.has(claim.status) ? 'supported' : 'contradicted'
}

export async function runReview(args) {
  const cases = JSON.parse(await readFile(new URL('./evidence-cases.json', import.meta.url), 'utf8'))
  const [command, path] = args
  if (args.length === 0) {
    const baseline = (review) => scoreReview(cases, cases.map((input) => ({ id: input.id, verdict: review(input) })))
    return { citation: baseline(citationBaseline), structured: baseline(structuredBaseline) }
  }
  if (command === '--inputs' && args.length === 1) {
    return cases.map(({ id, runId, claim, citations, evidence }) => ({ id, runId, claim, citations, evidence }))
  }
  if (command === '--predictions' && args.length === 2) {
    return scoreReview(cases, JSON.parse(await readFile(path, 'utf8')))
  }
  throw new Error('Use --inputs or --predictions <file>, or omit options to score both baselines.')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(JSON.stringify(await runReview(process.argv.slice(2)), null, 2))
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
