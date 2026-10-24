// A 401/403 from the gateway is a credential failure, not an outage, and a 401
// with `code: "workspace_deleted"` says so once per session
// (gatewaystack-connect#1693; mirrors claude-code-acp-plugin
// test/workspace-deleted-notice.test.mjs + test/429-is-a-verdict.test.mjs).
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { existsSync, mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, firstDeletedNotice } from '../index.js'

function fakeCtx() {
  const listeners = {}
  const warnings = []
  return {
    listeners,
    warnings,
    on: (event, fn) => { listeners[event] = fn },
    get: () => undefined,
    logger: { warn: m => warnings.push(m), info: () => {} },
  }
}

function stubGateway(status, json) {
  const server = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(json === undefined ? '' : JSON.stringify(json))
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => {
    resolve({ server, base: `http://127.0.0.1:${server.address().port}` })
  }))
}

const execFor = (sessionId = 'sess-1') => ({
  name: 'bash',
  arguments: { command: 'echo hi' },
  callId: 'call-1',
  signal: new AbortController().signal,
  agent: { session: { header: { id: sessionId, cwd: '/tmp' } } },
})
const NEXT = async () => ({ kind: 'allow' })
const DELETED = { error: 'workspace deleted', code: 'workspace_deleted' }

let home = ''
let savedHome
beforeEach(() => {
  savedHome = process.env.HOME
  home = mkdtempSync(join(tmpdir(), 'acp-dsh-keyrej-'))
  process.env.HOME = home // never touch the real ~/.acp
})
afterEach(() => { process.env.HOME = savedHome })

function mount(ctx, base, agentTier) {
  apply(ctx, { token: 'gsk_test_token', timeoutMs: 500, governBase: base, agentTier })
  return ctx.listeners['tools/pre-execute']
}

test('interactive 401 proceeds with KEY REJECTED naming the key and fix; lapse logged', async () => {
  const { server, base } = await stubGateway(401, { error: 'invalid key' })
  const ctx = fakeCtx()
  const decision = await mount(ctx, base, 'interactive')(execFor(), NEXT)
  server.close()
  assert.equal(decision.kind, 'allow')
  assert.match(ctx.warnings[0], /^\[ACP\] ⚠ KEY REJECTED \(HTTP 401\): the key in ~\/\.acp\/credentials is revoked or invalid/)
  assert.match(ctx.warnings[0], /install\.sh/)
  assert.match(ctx.warnings[0], /settings\/api-keys/)
  assert.doesNotMatch(ctx.warnings[0], /unreachable/i)
  assert.match(readFileSync(join(home, '.acp', 'lapse.log'), 'utf8'), /key rejected \(HTTP 401\)/)
})

test('unattended 401 stays denied with the cause named', async () => {
  const { server, base } = await stubGateway(401, undefined)
  const decision = await mount(fakeCtx(), base, 'background')(execFor(), NEXT)
  server.close()
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /Key rejected \(HTTP 401\)/)
  assert.match(decision.reason, /~\/\.acp\/credentials/)
  assert.doesNotMatch(decision.reason, /unreachable/i)
})

test('403 is treated like 401', async () => {
  const { server, base } = await stubGateway(403, { error: 'forbidden' })
  const ctx = fakeCtx()
  assert.equal((await mount(ctx, base, 'interactive')(execFor(), NEXT)).kind, 'allow')
  assert.match(ctx.warnings[0], /KEY REJECTED \(HTTP 403\)/)
  const d = await mount(fakeCtx(), base, 'subagent')(execFor(), NEXT)
  server.close()
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /Key rejected \(HTTP 403\)/)
})

test('5xx keeps the outage posture', async () => {
  const { server, base } = await stubGateway(503, { error: 'down' })
  const ctx = fakeCtx()
  assert.equal((await mount(ctx, base, 'interactive')(execFor(), NEXT)).kind, 'allow')
  assert.match(ctx.warnings[0], /UNGOVERNED: gateway unreachable \(HTTP 503/)
  const d = await mount(fakeCtx(), base, 'background')(execFor(), NEXT)
  server.close()
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /Gateway unreachable/)
})

test('interactive workspace_deleted: one notice per session, then silent; lapse logged every call', async () => {
  const { server, base } = await stubGateway(401, DELETED)
  const ctx = fakeCtx()
  const pre = mount(ctx, base, 'interactive')
  assert.equal((await pre(execFor('sess-a'), NEXT)).kind, 'allow')
  assert.equal(ctx.warnings.length, 1)
  assert.match(ctx.warnings[0], /workspace this machine was connected to has been deleted/)
  assert.match(ctx.warnings[0], /acp-uninstall/)
  assert.match(ctx.warnings[0], /uninstall\.sh/)
  assert.ok(existsSync(join(home, '.acp', 'notices', 'workspace-deleted.sess-a')))
  assert.equal((await pre(execFor('sess-a'), NEXT)).kind, 'allow')
  assert.equal(ctx.warnings.length, 1, 'silent after the first notice')
  await pre(execFor('sess-b'), NEXT)
  server.close()
  assert.equal(ctx.warnings.length, 2)
  assert.match(ctx.warnings[1], /has been deleted/)
  assert.equal(readFileSync(join(home, '.acp', 'lapse.log'), 'utf8').trim().split('\n').length, 3)
})

test('unattended workspace_deleted denies every call with the deleted message', async () => {
  const { server, base } = await stubGateway(401, DELETED)
  const pre = mount(fakeCtx(), base, 'background')
  for (let i = 0; i < 2; i++) {
    const d = await pre(execFor('sess-u'), NEXT)
    assert.equal(d.kind, 'deny')
    assert.match(d.reason, /has been deleted/)
    assert.match(d.reason, /acp-uninstall/)
  }
  server.close()
})

test('no session id: notice at most once per 24h', () => {
  const t0 = Date.parse('2026-10-24T00:00:00Z')
  assert.equal(firstDeletedNotice(undefined, t0), true)
  assert.equal(firstDeletedNotice(undefined, t0 + 60_000), false)
  assert.equal(firstDeletedNotice(undefined, t0 + 25 * 60 * 60 * 1000), true)
})
