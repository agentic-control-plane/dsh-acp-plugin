// Session receipt (gatewaystack-connect#606): one honest line at session end
// — calls governed, anything ACP said, deep link to THIS session — and
// nothing at all for sessions with zero governed calls.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { apply, buildReceiptMessage } from '../index.js'

function fakeCtx() {
  const listeners = {}
  const infos = []
  return {
    listeners,
    infos,
    on: (event, fn) => { listeners[event] = fn },
    get: () => undefined,
    logger: { warn: () => {}, info: m => infos.push(m) },
  }
}

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

const execFor = header => ({
  name: 'bash',
  arguments: { command: 'ls' },
  callId: 'call-1',
  signal: new AbortController().signal,
  agent: { session: { header } },
})

test('buildReceiptMessage: silent on zero calls, one line otherwise', () => {
  assert.equal(buildReceiptMessage({ calls: 0, denied: 0, asked: 0, notices: 0 }, 's'), null)
  assert.equal(buildReceiptMessage(null, 's'), null)
  const line = buildReceiptMessage({ calls: 3, denied: 1, asked: 0, notices: 2 }, 'sess/9')
  assert.match(line, /3 tool calls governed · 1 denied · 2 shadow notices/)
  assert.match(line, /sessions\/sess%2F9/) // session ids get URI-encoded
})

test('receipt prints once at main-agent dispose with aggregated counts', async () => {
  let call = 0
  const { server, base } = await stubGateway(() => {
    call += 1
    return { json: call === 3 ? { decision: 'deny', reason: 'no' } : { decision: 'allow' } }
  })
  const ctx = fakeCtx()
  apply(ctx, { token: 'gsk_test_token', governBase: base, timeoutMs: 500 })
  const pre = ctx.listeners['tools/pre-execute']
  const main = { id: 'sess-main', cwd: '/tmp' }
  await pre(execFor(main), async () => ({ kind: 'allow' }))
  await pre(execFor(main), async () => ({ kind: 'allow' }))
  await pre(execFor(main), async () => ({ kind: 'allow' })) // the deny

  ctx.listeners['agent/disposed']({ agent: { session: { header: main } } })
  assert.equal(ctx.infos.length, 1)
  assert.match(ctx.infos[0], /3 tool calls governed · 1 denied/)
  assert.match(ctx.infos[0], /sessions\/sess-main/)

  // A second dispose of the same session says nothing — the entry is gone.
  ctx.listeners['agent/disposed']({ agent: { session: { header: main } } })
  assert.equal(ctx.infos.length, 1)
  server.close()
})

test('subagent sessions fold into the parent receipt, no receipt of their own', async () => {
  const { server, base } = await stubGateway(() => ({ json: { decision: 'allow' } }))
  const ctx = fakeCtx()
  apply(ctx, { token: 'gsk_test_token', governBase: base, timeoutMs: 500 })
  const pre = ctx.listeners['tools/pre-execute']
  const main = { id: 'sess-main', cwd: '/tmp' }
  const child = { id: 'sess-child', cwd: '/tmp', parentSession: 'sess-main' }
  await pre(execFor(main), async () => ({ kind: 'allow' }))
  await pre(execFor(child), async () => ({ kind: 'allow' }))
  await pre(execFor(child), async () => ({ kind: 'allow' }))

  ctx.listeners['agent/disposed']({ agent: { session: { header: child } } })
  assert.equal(ctx.infos.length, 0) // subagent dispose is silent

  ctx.listeners['agent/disposed']({ agent: { session: { header: main } } })
  assert.equal(ctx.infos.length, 1)
  assert.match(ctx.infos[0], /3 tool calls governed/)
  server.close()
})

test('zero-call session dispose prints nothing', async () => {
  const { server, base } = await stubGateway(() => ({ json: { decision: 'allow' } }))
  const ctx = fakeCtx()
  apply(ctx, { token: 'gsk_test_token', governBase: base, timeoutMs: 500 })
  ctx.listeners['agent/disposed']({ agent: { session: { header: { id: 'sess-quiet', cwd: '/tmp' } } } })
  assert.equal(ctx.infos.length, 0)
  server.close()
})
