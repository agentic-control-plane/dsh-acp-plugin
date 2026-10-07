// ACP plugin conformance adapter (davidcrowe/gatewaystack-connect#1344).
//
// Drives dsh's REAL Cordis plugin (../index.js) against a fake gateway and
// asserts on what the person would see (ctx.logger.info, the only
// person-visible channel dsh has) and on the native tools/post-execute
// payload dsh actually sends to /govern/tool-output.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { readFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply } from '../index.js'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const CORPUS_PATH = join(HERE, 'fixtures', 'plugin-corpus.json')
const PINNED_FINGERPRINT = 'aa186d3fb3e7d18c' // sha256 of the raw corpus bytes, first 16 hex

const rawCorpus = readFileSync(CORPUS_PATH) // hash the raw bytes, never a re-serialised object
const fingerprint = createHash('sha256').update(rawCorpus).digest('hex').slice(0, 16)
if (fingerprint !== PINNED_FINGERPRINT) {
  throw new Error(
    `test/fixtures/plugin-corpus.json fingerprint mismatch: got ${fingerprint}, pinned ${PINNED_FINGERPRINT}. ` +
    'Re-vendor this file as a byte-identical copy of the canonical corpus.',
  )
}
const corpus = JSON.parse(rawCorpus.toString('utf8'))
const MARKER = corpus.marker // 'ACPCONF7F3A'
const casesById = Object.fromEntries(corpus.cases.map(c => [c.id, c]))

const PLUGIN = 'dsh-acp-plugin'
const rows = corpus.harnesses.filter(h => h.plugin === PLUGIN)
assert.ok(rows.length > 0, `corpus has no harness rows for ${PLUGIN}`)
const capabilityStatus = Object.fromEntries(rows.map(r => [r.capability, r]))

// dsh has no canonical tool-name remapping: apply()'s checkPayload() sets
// tool_name: exec.name verbatim (index.js ~L175), so the native tool name IS
// whatever the harness calls the tool — no translation layer to declare.
const NATIVE_TOOL_NAME = call => call.tool

// Cases known to currently FAIL for dsh on origin/main. Empty: dsh is not on
// the #1334 notice-drop list (codex, opencode, hermes, fx). If this ever
// stops being empty, add {case, issue, detail} and keep the assertion below
// asserting it fails — never patch plugin source from this adapter.
const EXPECTED_DIVERGENCES = []

/** Minimal Cordis-shaped ctx (same shape the existing dsh tests use). */
function fakeCtx() {
  const listeners = {}
  const info = []
  const warnings = []
  return {
    listeners,
    info,
    warnings,
    on: (event, fn) => { listeners[event] = fn },
    get: () => undefined,
    logger: { warn: m => warnings.push(String(m)), info: m => info.push(String(m)) },
  }
}

/**
 * Fake gateway on 127.0.0.1:0. /govern/tool-output replies with gatewayReply;
 * every other path (the tools/pre-execute check) replies allow. Records every
 * request's path + parsed JSON body.
 */
function stubGateway(gatewayReply) {
  const requests = []
  const server = createServer((req, res) => {
    let raw = ''
    req.on('data', c => { raw += c })
    req.on('end', () => {
      const body = raw ? JSON.parse(raw) : {}
      requests.push({ path: req.url, method: req.method, body })
      const json = req.url === '/govern/tool-output' ? gatewayReply : { decision: 'allow' }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(json))
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve({ server, requests, base: `http://127.0.0.1:${server.address().port}` })
  }))
}

/** Isolates HOME (dsh's credential-file and lapse-log lookups) per case. */
async function withEnv(env, fn) {
  const prevHome = process.env.HOME
  const prevShadow = process.env.ACP_SHADOW
  delete process.env.ACP_SHADOW // never let the developer machine's setting leak in
  process.env.HOME = mkdtempSync(join(tmpdir(), 'dsh-conf-home-'))
  for (const [k, v] of Object.entries(env)) process.env[k] = v
  try {
    return await fn()
  } finally {
    process.env.HOME = prevHome
    if (prevShadow === undefined) delete process.env.ACP_SHADOW
    else process.env.ACP_SHADOW = prevShadow
  }
}

const BASE_EXEC = {
  name: 'shell',
  arguments: { command: 'ls' },
  callId: 'call-conf',
  signal: new AbortController().signal,
  agent: { session: { header: { id: 'sess-conf', cwd: '/tmp' } } },
}

/** Runs a notice-capability case; returns { personSaw, channels }. */
async function runNoticeCase(kase) {
  return withEnv(kase.env ?? {}, async () => {
    const { server, base } = await stubGateway(kase.gatewayReply)
    const ctx = fakeCtx()
    apply(ctx, { governBase: base, token: 'gsk_test_conformance' })
    const post = ctx.listeners['tools/post-execute']
    await post(BASE_EXEC, { isError: false, content: [{ type: 'text', text: 'ok' }] }, async () => ({ kind: 'accept' }))
    server.close()
    const channels = { 'ctx.logger.info': ctx.info.join('\n'), 'ctx.logger.warn': ctx.warnings.join('\n') }
    const personSaw = Object.values(channels).some(s => s.includes(MARKER))
    return { channels, personSaw }
  })
}

/** Runs the post-tool-fields case; returns the recorded /govern/tool-output request. */
async function runPostToolCase(kase) {
  return withEnv(kase.env ?? {}, async () => {
    const { server, requests, base } = await stubGateway(kase.gatewayReply)
    const ctx = fakeCtx()
    apply(ctx, { governBase: base, token: 'gsk_test_conformance' })
    const post = ctx.listeners['tools/post-execute']
    const exec = {
      ...BASE_EXEC,
      name: NATIVE_TOOL_NAME(kase.call),
      arguments: { command: kase.call.command },
      agent: { session: { header: { id: kase.call.sessionId, cwd: '/tmp' } } },
    }
    await post(exec, { isError: false, content: [{ type: 'text', text: kase.call.output }] }, async () => ({ kind: 'accept' }))
    server.close()
    return requests.find(r => r.path === '/govern/tool-output')
  })
}

// --- notice capability ---
test('corpus: dsh-acp-plugin.notice status is "supported"', () => {
  assert.equal(capabilityStatus.notice?.status, 'supported')
})

for (const id of ['notice-shown', 'notice-shadow-off']) {
  const kase = casesById[id]
  const divergence = EXPECTED_DIVERGENCES.find(d => d.case === id)
  const label = divergence ? `EXPECTED DIVERGENCE ${divergence.issue}` : 'must pass'
  test(`notice ${id} on ctx.logger.info (${label})`, async () => {
    const { personSaw, channels } = await runNoticeCase(kase)
    const check = () => assert.equal(
      personSaw, kase.expect.personSees,
      `expected personSees=${kase.expect.personSees}; channels=${JSON.stringify(channels)}`,
    )
    if (divergence) {
      assert.throws(check, undefined, `${id} now passes — fixed, remove the EXPECTED_DIVERGENCES entry (issue ${divergence.issue})`)
    } else {
      check()
    }
  })
}

// --- post-tool capability ---
test('corpus: dsh-acp-plugin.post-tool status is "supported"', () => {
  assert.equal(capabilityStatus['post-tool']?.status, 'supported')
})

test('post-tool-fields: native tools/post-execute -> POST /govern/tool-output carries the contract fields', async () => {
  const kase = casesById['post-tool-fields']
  const divergence = EXPECTED_DIVERGENCES.find(d => d.case === 'post-tool-fields')
  const req = await runPostToolCase(kase)
  const check = () => {
    assert.ok(req, 'no /govern/tool-output request was recorded')
    assert.equal(req.method, 'POST')
    assert.equal(req.path, '/govern/tool-output')
    assert.equal(req.body.hook_event_name, 'PostToolUse')
    assert.equal(req.body.tool_name, NATIVE_TOOL_NAME(kase.call), 'tool_name must equal the native tool name (dsh applies no mapping)')
    assert.ok(JSON.stringify(req.body.tool_input).includes(MARKER), 'tool_input must carry the marker')
    assert.ok(JSON.stringify(req.body.tool_output).includes(MARKER), 'tool_output must carry the marker')
    assert.ok(typeof req.body.session_id === 'string' && req.body.session_id.length > 0, 'session_id must be a non-empty string')
  }
  if (divergence) {
    assert.throws(check, undefined, `post-tool-fields now passes — fixed, remove the EXPECTED_DIVERGENCES entry (issue ${divergence.issue})`)
  } else {
    check()
  }
})

// --- EXPECTED_DIVERGENCES must be exactly the known set: a NEW failure fails
// CI (nothing here catches it silently) and a FIX fails CI too, until the
// entry above is removed. ---
test('EXPECTED_DIVERGENCES is exactly the known set for dsh-acp-plugin', () => {
  assert.deepEqual(EXPECTED_DIVERGENCES, [])
})
