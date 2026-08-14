// Decision mapping + fail posture (gatewaystack-connect#385: interactive
// fails open LOUDLY, unattended fails closed; policy denies unaffected).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { apply } from '../index.js'

/** Minimal Cordis-shaped ctx that captures listeners and log lines. */
function fakeCtx({ approval } = {}) {
  const listeners = {}
  const warnings = []
  return {
    listeners,
    warnings,
    on: (event, fn) => { listeners[event] = fn },
    get: key => (key === 'approval' ? approval : undefined),
    logger: { warn: m => warnings.push(m), info: () => {} },
  }
}

/** One-route stub gateway; respond(url, body) decides per request. */
function stubGateway(respond) {
  const server = createServer((req, res) => {
    let raw = ''
    req.on('data', c => { raw += c })
    req.on('end', () => {
      const { status = 200, json = {} } = respond(req.url, JSON.parse(raw || '{}'))
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(json))
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
  }))
}

const EXEC = {
  name: 'bash',
  arguments: { command: 'rm -rf /' },
  callId: 'call-1',
  signal: new AbortController().signal,
  agent: { session: { header: { id: 'sess-1', cwd: '/tmp' } } },
}

function mount(ctx, config) {
  apply(ctx, { token: 'gsk_test_token', timeoutMs: 500, ...config })
  return ctx.listeners
}

test('policy deny maps to PreToolDecision deny with the reason', async () => {
  const { server, base } = await stubGateway(() => ({ json: { decision: 'deny', reason: 'blast radius' } }))
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: base })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Denied by policy: blast radius/)
  server.close()
})

test('policy ask maps to PreToolDecision ask (dsh approval flow resolves it)', async () => {
  const { server, base } = await stubGateway(() => ({ json: { decision: 'ask', reason: 'needs review' } }))
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: base })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /Approval required: needs review/)
  server.close()
})

test('policy allow delegates to next()', async () => {
  const { server, base } = await stubGateway((url, body) => {
    assert.equal(url, '/govern/tool-use')
    assert.equal(body.tool_name, 'bash')
    assert.equal(body.hook_event_name, 'PreToolUse')
    assert.equal(body.session_id, 'sess-1')
    return { json: { decision: 'allow' } }
  })
  const ctx = fakeCtx()
  let delegated = false
  const pre = mount(ctx, { governBase: base })['tools/pre-execute']
  const decision = await pre(EXEC, async () => { delegated = true; return { kind: 'allow' } })
  assert.equal(delegated, true)
  assert.equal(decision.kind, 'allow')
  server.close()
})

test('unreachable gateway + interactive tier fails OPEN with a loud warning', async () => {
  const ctx = fakeCtx()
  let delegated = false
  const pre = mount(ctx, { governBase: 'http://127.0.0.1:1', agentTier: 'interactive' })['tools/pre-execute']
  const decision = await pre(EXEC, async () => { delegated = true; return { kind: 'allow' } })
  assert.equal(delegated, true)
  assert.equal(decision.kind, 'allow')
  assert.ok(ctx.warnings.some(w => w.includes('UNGOVERNED')), 'lapse must be loud')
})

test('unreachable gateway + background tier fails CLOSED', async () => {
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: 'http://127.0.0.1:1', agentTier: 'background' })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /fail-closed for unattended agents/)
})

test('gateway 5xx follows the same outage posture, not a policy deny', async () => {
  const { server, base } = await stubGateway(() => ({ status: 503, json: {} }))
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: base, agentTier: 'background' })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Gateway unreachable/)
  server.close()
})

test('tier defaults: approval service mounted = interactive, headless = background', () => {
  const withApproval = fakeCtx({ approval: {} })
  mount(withApproval, { governBase: 'http://127.0.0.1:1' })
  const headless = fakeCtx()
  mount(headless, { governBase: 'http://127.0.0.1:1' })
  // Behavioral probe: outage under each default tier.
  return Promise.all([
    withApproval.listeners['tools/pre-execute'](EXEC, async () => ({ kind: 'allow' }))
      .then(d => assert.equal(d.kind, 'allow', 'approval mounted → interactive → fail-open')),
    headless.listeners['tools/pre-execute'](EXEC, async () => ({ kind: 'allow' }))
      .then(d => assert.equal(d.kind, 'deny', 'headless → background → fail-closed')),
  ])
})

test('no credential registers no policy listener and warns UNGOVERNED', () => {
  const ctx = fakeCtx()
  // Empty string is falsy but not nullish: it skips the ?? fallthrough to
  // ~/.acp/credentials (present on a dev machine) and hits the no-token path.
  apply(ctx, { token: '' })
  assert.equal(ctx.listeners['tools/pre-execute'], undefined)
  assert.ok(ctx.warnings.some(w => w.includes('UNGOVERNED')))
})

test('post-execute block turns the result into corrective feedback', async () => {
  const { server, base } = await stubGateway(url => url === '/govern/tool-output'
    ? { json: { action: 'block', reason: 'secrets in output' } }
    : { json: { decision: 'allow' } })
  const ctx = fakeCtx()
  const post = mount(ctx, { governBase: base })['tools/post-execute']
  const decision = await post(EXEC, { isError: false, content: [{ type: 'text', text: 'AKIA...' }] }, async () => ({ kind: 'accept' }))
  assert.equal(decision.kind, 'block')
  assert.match(decision.feedback[0].text, /secrets in output/)
  server.close()
})

test('a transport failure is retried once before the fail posture (#690)', async () => {
  // First request stalls past the budget, second answers immediately —
  // the confirmed shape of the incident: a slow ALLOW became a deny.
  let n = 0
  const server = createServer((req, res) => {
    n += 1
    const delay = n === 1 ? 400 : 0
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ decision: 'allow' }))
    }, delay)
  })
  const base = await new Promise(r => server.listen(0, '127.0.0.1', () =>
    r(`http://127.0.0.1:${server.address().port}`)))
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: base, agentTier: 'background', timeoutMs: 120 })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow', 'the retry must rescue a slow-but-successful answer')
  assert.equal(n, 2, 'exactly two attempts')
  server.close()
})

test('an HTTP status is never retried (a 429 must not be re-rolled)', async () => {
  let n = 0
  const { server, base } = await stubGateway(() => { n += 1; return { status: 429, json: {} } })
  const ctx = fakeCtx()
  const pre = mount(ctx, { governBase: base, agentTier: 'background' })['tools/pre-execute']
  const decision = await pre(EXEC, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.equal(n, 1, 'the server answered — do not retry')
  server.close()
})

test('post-execute outage is silent pass-through (the call already ran)', async () => {
  const ctx = fakeCtx()
  const post = mount(ctx, { governBase: 'http://127.0.0.1:1', agentTier: 'interactive' })['tools/post-execute']
  const decision = await post(EXEC, { isError: false, content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  assert.equal(decision.kind, 'accept')
  assert.equal(ctx.warnings.length, 0)
})
