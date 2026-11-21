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

// --- #1518 attended signal -------------------------------------------------

async function captureBodies(ctx, config, exec = EXEC) {
  const bodies = []
  const { server, base } = await stubGateway((url, body) => { bodies.push({ url, body }); return { json: { decision: 'allow' } } })
  const l = mount(ctx, { governBase: base, ...config })
  await l['tools/pre-execute'](exec, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](exec, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  server.close()
  return bodies
}

test('approval service mounted: attended claim true, approval-service source, native_ask', async () => {
  const [pre] = await captureBodies(fakeCtx({ approval: {} }), {})
  assert.deepEqual(pre.body.attended, { claim: true, source: 'approval-service' })
  assert.deepEqual(pre.body.capabilities, ['native_ask'])
})

test('no approval service: claim false, no native_ask', async () => {
  const [pre] = await captureBodies(fakeCtx(), {})
  assert.deepEqual(pre.body.attended, { claim: false, source: 'approval-service' })
  assert.equal(pre.body.capabilities, undefined)
})

test('a config/env tier override never sets the claim', async () => {
  const [pre] = await captureBodies(fakeCtx(), { agentTier: 'interactive' })
  assert.equal(pre.body.agent_tier, 'interactive')
  assert.equal(pre.body.attended.claim, false)
  const [pre2] = await captureBodies(fakeCtx({ approval: {} }), { agentTier: 'background' })
  assert.equal(pre2.body.agent_tier, 'background')
  assert.equal(pre2.body.attended.claim, true)
})

test('PostToolUse carries neither attended nor native_ask (only output_rewrite)', async () => {
  const bodies = await captureBodies(fakeCtx({ approval: {} }), {})
  const post = bodies.find(b => b.url === '/govern/tool-output')
  assert.ok(post)
  assert.equal(post.body.attended, undefined)
  // A text-only, untruncated result declares output_rewrite and nothing else.
  assert.deepEqual(post.body.capabilities, ['output_rewrite'])
})

// --- PII redaction on tool output -------------------------------------------

// Fake but realistic address, assembled so no literal sits in the fixture.
const EMAIL = 'dana' + '@northwind-mail.net'
const PII_NOTICE = '[ACP] Removed PII before the agent saw it: email.'
const PII = { types: ['email'], count: 1, action: 'redacted', applied: true }
const accept = async () => ({ kind: 'accept' })
const textResult = text => ({ isError: false, content: [{ type: 'text', text }] })

/** Mount against a stub that answers tool-output with `verdict`; records post bodies and info lines. */
async function postScenario(verdict, status = 200) {
  const seen = []
  const { server, base } = await stubGateway((url, body) => {
    if (url === '/govern/tool-output') { seen.push(body); return { status, json: verdict } }
    return { json: { decision: 'allow' } }
  })
  const ctx = fakeCtx()
  const infos = []
  ctx.logger.info = m => infos.push(m)
  const post = mount(ctx, { governBase: base })['tools/post-execute']
  return { seen, infos, server, post }
}

test('redact via modified_tool_response: declares output_rewrite, model gets redacted text', async () => {
  const { seen, server, post } = await postScenario({ action: 'redact', modified_tool_response: 'contact: [EMAIL]', pii: PII })
  try {
    const decision = await post(EXEC, textResult(`contact: ${EMAIL}`), accept)
    assert.deepEqual(seen[0].capabilities, ['output_rewrite'])
    assert.equal(seen[0].tool_output, `contact: ${EMAIL}`)
    assert.equal(seen[0].tool_response, undefined, 'no tool_response is sent')
    assert.equal(decision.kind, 'accept')
    assert.deepEqual(decision.content, [{ type: 'text', text: 'contact: [EMAIL]' }])
  } finally { server.close() }
})

test('redact via legacy modified_output: model gets redacted text', async () => {
  const { server, post } = await postScenario({ action: 'redact', modified_output: 'contact: [EMAIL]', pii: PII })
  try {
    const decision = await post(EXEC, textResult(`contact: ${EMAIL}`), accept)
    assert.deepEqual(decision.content, [{ type: 'text', text: 'contact: [EMAIL]' }])
  } finally { server.close() }
})

test('non-text block: no capability declared, no rewrite', async () => {
  const { seen, server, post } = await postScenario({
    action: 'redact', modified_output: 'contact: [EMAIL]', pii: { ...PII, action: 'detected', applied: false },
  })
  try {
    const result = {
      isError: false,
      content: [
        { type: 'text', text: `contact: ${EMAIL}` },
        { type: 'image', data: 'iVBORw0KGgo=', mimeType: 'image/png' },
      ],
    }
    const decision = await post(EXEC, result, accept)
    assert.equal(seen[0].capabilities, undefined)
    assert.deepEqual(decision, { kind: 'accept' }, 'original (with image) passes through')
  } finally { server.close() }
})

test('truncated output: no capability declared, no rewrite', async () => {
  const { seen, server, post } = await postScenario({ action: 'redact', modified_output: 'x' })
  try {
    const decision = await post(EXEC, textResult(`${EMAIL} ` + 'a'.repeat(201 * 1024)), accept)
    assert.equal(seen[0].capabilities, undefined)
    assert.deepEqual(decision, { kind: 'accept' })
  } finally { server.close() }
})

test('PII notice prints verbatim on redact, even with ACP_SHADOW=off', async () => {
  process.env.ACP_SHADOW = 'off'
  const { infos, server, post } = await postScenario({
    action: 'redact', modified_tool_response: 'contact: [EMAIL]', pii: PII, notice: PII_NOTICE,
  })
  try {
    await post(EXEC, textResult(`contact: ${EMAIL}`), accept)
    assert.deepEqual(infos, [PII_NOTICE])
  } finally { delete process.env.ACP_SHADOW; server.close() }
})

test('notice prints on block too', async () => {
  const { infos, server, post } = await postScenario({ action: 'block', reason: 'pii', pii: PII, notice: PII_NOTICE })
  try {
    const decision = await post(EXEC, textResult(`contact: ${EMAIL}`), accept)
    assert.equal(decision.kind, 'block')
    assert.deepEqual(infos, [PII_NOTICE])
  } finally { server.close() }
})

test('shadow notice on pass is still silenced by ACP_SHADOW=off', async () => {
  process.env.ACP_SHADOW = 'off'
  const { infos, server, post } = await postScenario({ action: 'pass', notice: '[ACP] shadow: would have asked' })
  try {
    await post(EXEC, textResult('ok'), accept)
    assert.equal(infos.length, 0)
  } finally { delete process.env.ACP_SHADOW; server.close() }
})

test('gateway error on tool-output: original passes through', async () => {
  const { server, post } = await postScenario({ error: 'boom' }, 500)
  try {
    const decision = await post(EXEC, textResult(`contact: ${EMAIL}`), accept)
    assert.deepEqual(decision, { kind: 'accept' })
  } finally { server.close() }
})

// --- A call that never ran is not reported as tool output.
// dsh routes a denied / declined / cancelled call through tools/post-execute
// with its own "Error: <reason>" text; that is not output from the tool.

/** Stub that records every request path and answers pre with `decision`. */
async function recordingGateway(decision) {
  const seen = []
  const { server, base } = await stubGateway((url) => {
    seen.push(url)
    return url === '/govern/tool-use'
      ? { json: { decision, reason: 'because' } }
      : { json: { action: 'pass' } }
  })
  return { server, base, seen }
}
const exec = id => ({ ...EXEC, callId: id })
const harnessDenial = reason => ({ content: [{ type: 'text', text: `Error: ${reason}` }], isError: true, error: { message: reason } })
const posts = seen => seen.filter(u => u === '/govern/tool-output').length

test('a denied call is not reported as tool output', async () => {
  const { server, base, seen } = await recordingGateway('deny')
  const l = mount(fakeCtx(), { governBase: base })
  const e = exec('deny-1')
  const d = await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  assert.equal(d.kind, 'deny')
  const out = await l['tools/post-execute'](e, harnessDenial(d.reason), async () => ({ kind: 'accept' }))
  assert.deepEqual(out, { kind: 'accept' })
  assert.equal(posts(seen), 0)
  server.close()
})

test('a fail-closed deny (gateway down, unattended) is not reported either', async () => {
  const { server, base, seen } = await recordingGateway('allow')
  const l = mount(fakeCtx(), { governBase: 'http://127.0.0.1:9', agentTier: 'background' })
  const e = exec('down-1')
  const d = await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  assert.equal(d.kind, 'deny')
  // Point is the bookkeeping, not the transport: the post must not be attempted.
  let nextCalls = 0
  await l['tools/post-execute'](e, harnessDenial(d.reason), async () => { nextCalls++; return { kind: 'accept' } })
  assert.equal(nextCalls, 1)
  assert.equal(posts(seen), 0)
  server.close()
})

test('an allowed call that the harness dispatched is reported', async () => {
  const { server, base, seen } = await recordingGateway('allow')
  const l = mount(fakeCtx(), { governBase: base })
  const e = exec('run-1')
  await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  await l['tools/execute'](e, async () => ({ content: [{ type: 'text', text: 'ok' }] }))
  await l['tools/post-execute'](e, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  server.close()
})

test('an approved ask that ran is reported; a declined ask is not', async () => {
  const { server, base, seen } = await recordingGateway('ask')
  const l = mount(fakeCtx({ approval: {} }), { governBase: base })
  const yes = exec('ask-yes')
  assert.equal((await l['tools/pre-execute'](yes, async () => ({ kind: 'allow' }))).kind, 'ask')
  await l['tools/execute'](yes, async () => ({ content: [{ type: 'text', text: 'pushed' }] }))
  await l['tools/post-execute'](yes, { content: [{ type: 'text', text: 'pushed' }] }, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  const no = exec('ask-no')
  await l['tools/pre-execute'](no, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](no, harnessDenial('approval declined'), async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  server.close()
})

test('a declined ask is not reported even before any call has been dispatched', async () => {
  const { server, base, seen } = await recordingGateway('ask')
  const l = mount(fakeCtx({ approval: {} }), { governBase: base })
  const no = exec('ask-first')
  await l['tools/pre-execute'](no, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](no, harnessDenial('approval declined'), async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 0)
  server.close()
})

test('a call aborted before dispatch is not reported, even after tools/execute fired', async () => {
  const { server, base, seen } = await recordingGateway('allow')
  const l = mount(fakeCtx(), { governBase: base })
  const e = exec('abort-1')
  await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  // A later wrapper short-circuits on an aborted signal: the body never runs.
  await l['tools/execute'](e, async () => ({ content: [] }))
  const aborted = {
    content: [{ type: 'text', text: 'Error: tool call aborted before dispatch' }],
    isError: true,
    error: { message: 'tool call aborted before dispatch', info: { name: 'AbortError', code: 'ABORTED_BEFORE_DISPATCH' } },
  }
  await l['tools/post-execute'](e, aborted, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 0)
  server.close()
})

test('an approved ask whose tool then failed is still reported', async () => {
  const { server, base, seen } = await recordingGateway('ask')
  const l = mount(fakeCtx({ approval: {} }), { governBase: base })
  const e = exec('ask-fail')
  await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  await l['tools/execute'](e, async () => ({ content: [], isError: true }))
  await l['tools/post-execute'](e, { content: [{ type: 'text', text: 'fatal: remote rejected' }], isError: true }, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  server.close()
})

test('an allowed call that errors without reaching tools/execute is still reported', async () => {
  // A dsh guard or another plugin stopped it. Not ours to recognise; the
  // rule is that a miss sends a report rather than dropping real output.
  const { server, base, seen } = await recordingGateway('allow')
  const l = mount(fakeCtx(), { governBase: base })
  const ran = exec('mix-1')
  await l['tools/pre-execute'](ran, async () => ({ kind: 'allow' }))
  await l['tools/execute'](ran, async () => ({ content: [] }))
  await l['tools/post-execute'](ran, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  const other = exec('mix-2')
  await l['tools/pre-execute'](other, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](other, harnessDenial('guard'), async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 2)
  server.close()
})

test('a deny in one session does not hide a real call that reuses the call id in another', async () => {
  let n = 0
  const seen = []
  const { server, base } = await stubGateway((url) => {
    seen.push(url)
    if (url !== '/govern/tool-use') return { json: { action: 'pass' } }
    return { json: { decision: n++ === 0 ? 'deny' : 'allow', reason: 'because' } }
  })
  const l = mount(fakeCtx(), { governBase: base })
  const inSession = sid => ({ ...EXEC, callId: 'call_0', agent: { session: { header: { id: sid, cwd: '/tmp' } } } })
  // Denied in session A, and its post-execute never arrives (final-result path).
  await l['tools/pre-execute'](inSession('A'), async () => ({ kind: 'allow' }))
  const b = inSession('B')
  await l['tools/pre-execute'](b, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](b, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  server.close()
})

test('a harness that never emits tools/execute still gets allowed calls reported', async () => {
  const { server, base, seen } = await recordingGateway('allow')
  const l = mount(fakeCtx(), { governBase: base })
  const e = exec('old-1')
  await l['tools/pre-execute'](e, async () => ({ kind: 'allow' }))
  await l['tools/post-execute'](e, { content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
  assert.equal(posts(seen), 1)
  server.close()
})
