/**
 * Agentic Control Plane for DeepSeek Harness (dsh).
 *
 * A native Cordis plugin on the harness's typed interception points:
 *
 *   tools/pre-execute  -> POST {ACP_GOVERN}/govern/tool-use   (allow / ask / deny)
 *   tools/post-execute -> POST {ACP_GOVERN}/govern/tool-output (audit / DLP / shadow notices)
 *
 * Decision mapping onto dsh's PreToolDecision:
 *   allow -> delegate to next()
 *   ask   -> { kind: 'ask', reason }  (dsh's own approval service resolves it;
 *            with no approval service mounted, dsh denies — headless runs
 *            fail closed on ask, which is the correct unattended posture)
 *   deny  -> { kind: 'deny', reason }
 *
 * Unreachability posture (gatewaystack-connect#385, never-brick): interactive
 * sessions fail OPEN with a loud UNGOVERNED warning and a ~/.acp/lapse.log
 * entry; unattended tiers fail CLOSED — nobody is watching, so the block is
 * the safety net. Policy denies are unaffected; this posture only covers the
 * inability to ASK the policy.
 *
 * @module dsh-plugin-acp
 */

import { appendFileSync, mkdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'acp'

export const PLUGIN_VERSION = '0.1.3'

/** 200 KB ceiling on tool output sent for post-hoc scanning (matches the backend). */
const POST_HOOK_PAYLOAD_CEILING = 200 * 1024

/** Hook decision budget: control-plane calls answer fast or get out of the way. */
const CHECK_TIMEOUT_MS = 4000

function readToken() {
  if (process.env.ACP_BEARER_TOKEN) return process.env.ACP_BEARER_TOKEN
  // Same order as the other harness plugins' credential lookup — keep in sync.
  for (const file of ['credentials', 'proxy-key']) {
    try {
      const value = readFileSync(join(homedir(), '.acp', file), 'utf8').trim()
      if (value) return value
    } catch { /* absent or unreadable — try the next path */ }
  }
  return null
}

function lapseLine(fields) {
  try {
    mkdirSync(join(homedir(), '.acp'), { recursive: true })
    appendFileSync(
      join(homedir(), '.acp', 'lapse.log'),
      JSON.stringify({ at: new Date().toISOString(), client: 'dsh-plugin', ...fields }) + '\n',
    )
  } catch { /* the lapse log is best-effort — never block a call on it */ }
}

export function apply(ctx, config = {}) {
  const govern = (
    config.governBase
    ?? process.env.ACP_GOVERN_BASE
    ?? process.env.ACP_API_BASE
    ?? 'https://govern.agenticcontrolplane.com'
  ).replace(/\/$/, '')
  const token = config.token ?? readToken()

  // dsh has no permission_mode; tier follows who can answer an ask. An
  // approval service mounted means a human is reachable (interactive);
  // headless compositions have nobody watching (background). Config wins.
  const resolveTier = () => config.agentTier
    ?? process.env.ACP_AGENT_TIER
    ?? (ctx.get('approval') !== undefined ? 'interactive' : 'background')

  if (!token) {
    // Loud, once per load, plus a durable lapse line per session start —
    // an uncredentialed control plane must never be mistaken for a live one.
    ctx.logger.warn(
      '[ACP] ⚠ UNGOVERNED: no credential (ACP_BEARER_TOKEN or ~/.acp/credentials) — '
      + 'tool calls run WITHOUT policy checks and ACP has no record of them. '
      + 'Connect at https://cloud.agenticcontrolplane.com',
    )
    ctx.on('agent/session-start', ({ agent }) => {
      lapseLine({ kind: 'UNGOVERNED', reason: 'no-credentials', session: agent.session.header.id })
    })
    return
  }

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
    'X-GS-Client': `dsh-plugin/${PLUGIN_VERSION}`,
  }

  async function post(path, payload, signal) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), config.timeoutMs ?? CHECK_TIMEOUT_MS)
    const abort = () => controller.abort()
    signal?.addEventListener('abort', abort, { once: true })
    try {
      const res = await fetch(`${govern}${path}`, {
        method: 'POST', headers, body: JSON.stringify(payload), signal: controller.signal,
      })
      if (!res.ok) {
        // Tagged so the pre-execute retry can tell "the server answered with
        // a status" from "the request never landed". Re-rolling a 429 would
        // deepen the rate limit it is reporting.
        const err = new Error(`HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}`)
        err.httpStatus = res.status
        throw err
      }
      return await res.json()
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
    }
  }

  function checkPayload(exec, event) {
    return {
      tool_name: exec.name,
      tool_input: exec.arguments,
      session_id: exec.agent?.session.header.id,
      call_id: exec.callId,
      cwd: exec.agent?.session.header.cwd,
      hook_event_name: event,
      agent_tier: resolveTier(),
    }
  }

  // --- Pre-call policy check: the decision happens before the tool runs. ---
  ctx.on('tools/pre-execute', async (exec, next) => {
    let data
    try {
      try {
        data = await post('/govern/tool-use', checkPayload(exec, 'PreToolUse'), exec.signal)
      } catch (first) {
        // Retry once before applying the fail posture (gatewaystack-connect#690).
        // A confirmed incident on the Claude Code plugin: the gateway answered
        // HTTP 200 — an allow — at 4.635s, after the client had aborted at 4s,
        // and the unattended tier turned that allow into a deny. The slow
        // answers are cold starts, so the retry lands on a warm instance.
        // Retry only a transport failure: an HTTP status is the server
        // answering, and a caller-cancelled call is already gone.
        if (first?.httpStatus !== undefined || exec.signal?.aborted) throw first
        data = await post('/govern/tool-use', checkPayload(exec, 'PreToolUse'), exec.signal)
      }
    } catch (error) {
      const detail = error?.name === 'AbortError' ? 'request timed out' : (error?.message ?? 'network error')
      const tier = resolveTier()
      if (tier === 'interactive') {
        // Lapse loudly and leave the audit trail ACP never saw.
        lapseLine({ kind: 'UNGOVERNED', tool: exec.name, tier, detail })
        ctx.logger.warn(`[ACP] ⚠ UNGOVERNED: gateway unreachable (${detail}) — ${exec.name} proceeded WITHOUT policy check. Lapse logged to ~/.acp/lapse.log.`)
        return next()
      }
      // Unattended tier: hold the line, say why honestly.
      return {
        kind: 'deny',
        reason: `[ACP] Gateway unreachable (${detail}) — ${tier} tier stays blocked when policy can't be consulted (fail-closed for unattended agents; interactive sessions fail open).`,
      }
    }
    if (data.decision === 'deny') {
      return { kind: 'deny', reason: `[ACP] Denied by policy: ${data.reason ?? 'policy did not return a reason'}` }
    }
    if (data.decision === 'ask') {
      return { kind: 'ask', reason: `[ACP] Approval required: ${data.reason ?? 'approval required'}` }
    }
    if (data.warning) ctx.logger.warn(String(data.warning))
    return next()
  })

  // --- Post-call audit: the result is reported for scanning; a server block
  // turns the result into corrective feedback the model sees. ---
  ctx.on('tools/post-execute', async (exec, result, next) => {
    let outputStr = ''
    try {
      outputStr = result.content
        .map(block => block.type === 'text' ? block.text : `[${block.type} content]`)
        .join('\n')
    } catch { return next() }
    if (Buffer.byteLength(outputStr, 'utf8') > POST_HOOK_PAYLOAD_CEILING) {
      outputStr = outputStr.slice(0, POST_HOOK_PAYLOAD_CEILING)
    }
    let data
    try {
      data = await post('/govern/tool-output', {
        ...checkPayload(exec, 'PostToolUse'),
        tool_output: outputStr,
      }, exec.signal)
    } catch {
      // Post-hoc scanning is observability: silent pass-through, the call
      // already ran. The pre-call check is where unreachability gets loud.
      return next()
    }
    if (data.action === 'block') {
      return {
        kind: 'block',
        feedback: [{ type: 'text', text: `[ACP] Blocked: ${data.reason ?? 'policy'}` }],
      }
    }
    if (data.action === 'redact' && typeof data.tool_output === 'string') {
      // DLP/ad-block rewrite: the model sees the transformed output.
      return next().then(downstream => downstream.kind === 'accept' && downstream.content === undefined && downstream.value === undefined
        ? { ...downstream, content: [{ type: 'text', text: data.tool_output }] }
        : downstream)
    }
    if (typeof data.notice === 'string' && data.notice.trim() && !/^(off|0|false)$/i.test(process.env.ACP_SHADOW ?? '')) {
      // Shadow-mode counterfactual (#607): advisory, arrives with action "pass".
      ctx.logger.info(data.notice)
    }
    return next()
  })
}
