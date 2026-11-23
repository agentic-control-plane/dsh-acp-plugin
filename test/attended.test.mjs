// Attended claim: a person can be asked only when dsh's approval service is
// mounted, stdin and stdout are terminals, and the run is not CI. In every
// other case a gateway ask is turned into a deny.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { apply, hasTerminal } from '../index.js'

// Each case sets CI itself; the runner's own CI variable must not decide them.
delete process.env.CI

function fakeCtx({ approval } = {}) {
  const listeners = {}
  return {
    listeners,
    on: (event, fn) => { listeners[event] = fn },
    get: key => (key === 'approval' ? approval : undefined),
    logger: { warn: () => {}, info: () => {} },
  }
}

/** Stub gateway answering tool-use with `verdict`; records every request. */
function stubGateway(verdict) {
  const seen = []
  const server = createServer((req, res) => {
    let raw = ''
    req.on('data', c => { raw += c })
    req.on('end', () => {
      seen.push({ url: req.url, body: JSON.parse(raw || '{}') })
      const json = req.url === '/govern/tool-use' ? verdict : { action: 'pass' }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(json))
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve({ server, seen, base: `http://127.0.0.1:${server.address().port}` })
  }))
}

const EXEC = {
  name: 'bash',
  arguments: { command: 'echo probe' },
  callId: 'call-1',
  signal: new AbortController().signal,
  agent: { session: { header: { id: 'sess-1', cwd: '/tmp' } } },
}

/** Run one pre-execute (and a post-execute) against `verdict`; returns decision + bodies. */
async function run({ approval, tty, ci, verdict = { decision: 'allow' } }) {
  const { server, seen, base } = await stubGateway(verdict)
  if (ci !== undefined) process.env.CI = ci
  try {
    const ctx = fakeCtx({ approval })
    apply(ctx, { token: 'gsk_test_token', timeoutMs: 500, governBase: base, ttyForTest: tty })
    const decision = await ctx.listeners['tools/pre-execute'](EXEC, async () => ({ kind: 'allow' }))
    await ctx.listeners['tools/post-execute'](EXEC, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
    const pre = seen.find(s => s.url === '/govern/tool-use')?.body
    const post = seen.find(s => s.url === '/govern/tool-output')?.body
    return { decision, pre, post }
  } finally {
    delete process.env.CI
    server.close()
  }
}

test('approval service + both TTYs + no CI: claim true, mode tty, native_ask', async () => {
  const { pre } = await run({ approval: {}, tty: { stdin: true, stdout: true } })
  assert.deepEqual(pre.attended, { claim: true, source: 'approval-service', mode: 'tty' })
  assert.deepEqual(pre.capabilities, ['native_ask'])
})

test('no approval service: claim false, mode no-approval-service, no native_ask', async () => {
  const { pre } = await run({ tty: true })
  assert.deepEqual(pre.attended, { claim: false, source: 'approval-service', mode: 'no-approval-service' })
  assert.ok(!(pre.capabilities ?? []).includes('native_ask'))
})

test('no terminal: claim false, mode no-tty, no native_ask', async () => {
  for (const tty of [false, { stdin: false, stdout: true }, { stdin: true, stdout: false }, { stdin: undefined, stdout: undefined }]) {
    const { pre } = await run({ approval: {}, tty })
    assert.deepEqual(pre.attended, { claim: false, source: 'approval-service', mode: 'no-tty' })
    assert.ok(!(pre.capabilities ?? []).includes('native_ask'))
  }
})

test('CI run: claim false, mode ci, no native_ask', async () => {
  const { pre } = await run({ approval: {}, tty: true, ci: 'true' })
  assert.deepEqual(pre.attended, { claim: false, source: 'approval-service', mode: 'ci' })
  assert.ok(!(pre.capabilities ?? []).includes('native_ask'))
})

test('hasTerminal needs both streams to be TTYs', () => {
  assert.equal(hasTerminal(true), true)
  assert.equal(hasTerminal(false), false)
  assert.equal(hasTerminal({ stdin: true, stdout: true }), true)
  assert.equal(hasTerminal({ stdin: true, stdout: false }), false)
  assert.equal(hasTerminal({ stdin: undefined, stdout: true }), false)
})

const ASK_REASON = 'ACP (Agentic Control Plane) asks: run `echo probe`? Your rule: shell → ask. https://cloud.agenticcontrolplane.com/activity/abc?x=1&y=<2>'

test('ask with claim true: kind ask, gateway reason passed through unchanged', async () => {
  const { decision } = await run({ approval: {}, tty: true, verdict: { decision: 'ask', reason: ASK_REASON } })
  assert.deepEqual(decision, { kind: 'ask', reason: ASK_REASON })
})

test('ask with claim true: a reason without the ACP prefix keeps the old wording', async () => {
  const { decision } = await run({ approval: {}, tty: true, verdict: { decision: 'ask', reason: 'needs review' } })
  assert.deepEqual(decision, { kind: 'ask', reason: '[ACP] Approval required: needs review' })
})

test('ask with no terminal: deny that names why and carries the gateway reason unchanged', async () => {
  const { decision } = await run({ approval: {}, tty: false, verdict: { decision: 'ask', reason: ASK_REASON } })
  assert.equal(decision.kind, 'deny')
  assert.ok(decision.reason.includes(ASK_REASON))
  assert.ok(decision.reason.endsWith(ASK_REASON), 'the console link stays at the end')
  assert.equal(
    decision.reason,
    "[ACP] This call needs a person's approval and dsh cannot ask here (there is no terminal), so it is blocked. Approve it in the ACP console, then run it again.\n\n" + ASK_REASON,
  )
})

test('ask in a CI run: deny that names CI and carries the gateway reason unchanged', async () => {
  const { decision } = await run({ approval: {}, tty: true, ci: '1', verdict: { decision: 'ask', reason: ASK_REASON } })
  assert.equal(decision.kind, 'deny')
  assert.ok(decision.reason.includes('(this is a CI run)'))
  assert.ok(decision.reason.endsWith(`\n\n${ASK_REASON}`))
})

test('ask with no approval service: deny that names the missing service', async () => {
  const { decision } = await run({ tty: true, verdict: { decision: 'ask', reason: ASK_REASON } })
  assert.equal(decision.kind, 'deny')
  assert.ok(decision.reason.includes('(no approval service is mounted)'))
  assert.ok(decision.reason.endsWith(ASK_REASON))
})

test('an ask turned into a deny is not reported as tool output', async () => {
  const { server, seen, base } = await stubGateway({ decision: 'ask', reason: ASK_REASON })
  try {
    const ctx = fakeCtx({ approval: {} })
    apply(ctx, { token: 'gsk_test_token', timeoutMs: 500, governBase: base, ttyForTest: false })
    const d = await ctx.listeners['tools/pre-execute'](EXEC, async () => ({ kind: 'allow' }))
    assert.equal(d.kind, 'deny')
    const denial = { content: [{ type: 'text', text: `Error: ${d.reason}` }], isError: true, error: { message: d.reason } }
    await ctx.listeners['tools/post-execute'](EXEC, denial, async () => ({ kind: 'accept' }))
    assert.equal(seen.filter(s => s.url === '/govern/tool-output').length, 0)
  } finally { server.close() }
})

test('PostToolUse carries neither attended nor native_ask', async () => {
  const { post } = await run({ approval: {}, tty: true })
  assert.ok(post)
  assert.equal(post.attended, undefined)
  assert.ok(!(post.capabilities ?? []).includes('native_ask'))
})
