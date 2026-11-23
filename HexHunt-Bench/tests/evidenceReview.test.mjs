import assert from 'node:assert/strict'
import test from 'node:test'
import { runReview, scoreReview } from '../review/score-review.mjs'

test('the evidence suite exposes unsupported claims that pass a citation check', async () => {
  const { citation, structured } = await runReview([])
  assert.equal(citation.cases, 7)
  assert.equal(citation.correct, 4)
  assert.equal(citation.falseSupport, 3)
  assert.equal(structured.correct, 7)
  assert.equal(structured.falseSupport, 0)
})

test('review inputs omit answers and the scorer requires a verdict for every case', async () => {
  const inputs = await runReview(['--inputs'])
  assert.ok(inputs.every((input) => !('expected' in input)))
  const cases = [{ id: 'example', expected: 'insufficient' }]
  assert.throws(() => scoreReview(cases, []), /every case/)
  assert.throws(() => scoreReview(cases, [
    { id: 'example', verdict: 'insufficient' },
    { id: 'example', verdict: 'supported' },
  ]), /duplicate/)
  assert.throws(() => scoreReview(cases, [{ id: 'example', verdict: 'maybe' }]), /Invalid/)
})
