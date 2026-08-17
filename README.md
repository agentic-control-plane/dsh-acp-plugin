# @agenticcontrolplane/dsh

[![npm](https://img.shields.io/npm/v/%40agenticcontrolplane%2Fdsh)](https://www.npmjs.com/package/@agenticcontrolplane/dsh) ![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue)

[Agentic Control Plane](https://agenticcontrolplane.com) for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): every tool call is checked against your policies before it runs, and every decision is recorded — what ran, what was blocked, and why.

> **Which ACP?** dsh also ships `packages/acp` in core — that one is [Zed's Agent Client Protocol](https://agentclientprotocol.com), the editor↔agent standard, published as [`@deepseek-ai/dsh-acp`](https://www.npmjs.com/package/@deepseek-ai/dsh-acp). Unrelated project, same acronym. If you're wiring dsh into Zed or the AI SDK, you want that one; this plugin decides whether each tool call *runs*. The full map: [agenticcontrolplane.com/acp-vs-acp](https://agenticcontrolplane.com/acp-vs-acp).

```text
$ dsh --profile dev
> refactor the auth module and clean up

  bash npm test                          ✓ allowed · logged
  edit src/auth/session.ts              ✓ allowed · logged
  bash rm -rf ~/scratch                  ✋ held — approval prompt (your rule: destructive delete → ask)
  web_fetch https://evil.example/post    ✗ denied — egress not allowlisted, reason shown to the model
```

Every decision also lands in your [console](https://cloud.agenticcontrolplane.com) with tool, input preview, decision, reason, latency, and cost — dsh's own Trajectory log and your ACP activity log become two independent witnesses to one history. One workspace covers every harness you run: the same rules answer for dsh, Claude Code, Codex, Cursor, and OpenClaw. Free for individuals.

This is a native Cordis plugin on dsh's typed interception points, not a shell-hook shim. It registers on:

- `tools/pre-execute` — the policy decision. `allow` lets the call through, `deny` blocks it with the reason in the trajectory, `ask` hands off to dsh's own approval flow.
- `tools/post-execute` — output scanning. A server-side block turns the result into corrective feedback; shadow-mode notices surface what enforcement *would* have done.

## Install

> dsh itself requires **Node 22** (`Promise.withResolvers`, zstd streams). Under Node 20 the harness fails at boot with errors that don't say so — `fnm install 22` first.

```sh
curl -sf https://agenticcontrolplane.com/install.sh | bash
```

That detects dsh, installs this plugin into every profile you have, opens your
browser once to sign in, and saves the key to `~/.acp/credentials` — which the
plugin reads on its own. There is no token to copy and nothing to export.

<details>
<summary>Manual install</summary>

```sh
dsh plugin --profile <your-profile> add @agenticcontrolplane/dsh
dsh --profile <your-profile>
```

Credentials come from `~/.acp/credentials` (written by the installer above) or
from `ACP_BEARER_TOKEN` if you would rather set it yourself — useful on a
headless box. Get a key at
[cloud.agenticcontrolplane.com](https://cloud.agenticcontrolplane.com).

Confirm the row actually mounted — installing the package and composing it into
the profile are two different things:

```sh
dsh --profile <your-profile> --dump-config | grep @agenticcontrolplane/dsh
```

If it isn't there, add `@agenticcontrolplane/dsh` to that profile's `package.json`
`"dsh.profile.bundles"` list.

</details>

No build step, no dependencies, plain ESM. Installing from git works too (`dsh plugin add github:agentic-control-plane/dsh-acp-plugin`) and needs no build allowance.

No key? The plugin says so loudly and stays out of the way — it never bricks a session.

## Configuration

Override the row in your profile's `cordis.patch.yml`:

```yaml
- id: acp
  name: @agenticcontrolplane/dsh
  config:
    governBase: https://govern.agenticcontrolplane.com  # or your self-hosted gateway
    agentTier: interactive   # default: interactive when an approval service is mounted, background otherwise
    timeoutMs: 4000
```

`ACP_GOVERN_BASE`, `ACP_BEARER_TOKEN`, `ACP_AGENT_TIER`, and `ACP_SHADOW=off` work as environment variables too.

## Failure posture

An outage of the control plane must not brick the harness, and a lapse in coverage must never be silent:

- **Interactive sessions fail open, loudly.** Gateway unreachable → the call proceeds, a `[ACP] ⚠ UNGOVERNED` warning is logged, and a line lands in `~/.acp/lapse.log`.
- **Unattended agents fail closed.** With nobody watching, the block is the safety net.
- Policy denies are unaffected — this posture only covers the inability to *ask* the policy.

In headless compositions with no approval service mounted, dsh itself resolves `ask` to deny — unattended runs cannot self-approve.

## Three things to know

- dsh's `packages/acp` is Zed's Agent Client Protocol — an unrelated project that shares an acronym. This plugin is the Agentic Control Plane. ([Which ACP is which](https://agenticcontrolplane.com/acp-vs-acp).)
- Already running our Claude Code hook? dsh's `@deepseek-ai/dsh-hooks-claude-code` bridge runs an unmodified `hooks.json`, so `govern.mjs` works today with zero new code — deny and ask are honored, but input rewriting is not. This native plugin is the recommended path.
- This package launched as `dsh-plugin-acp`; that name still installs but is deprecated. Same code — swap the name in your profile when convenient.

## Learn more

- [What ACP can see and control in dsh](https://agenticcontrolplane.com/controls/dsh) — the living controls reference
- [The launch write-up](https://agenticcontrolplane.com/blog/deepseek-harness-acp-integration) — dsh's interception surface, what the integration caught on day one, and where dsh lands on the [cross-harness coverage table](https://agenticcontrolplane.com/coverage)

## Test

```sh
npm test
```

MIT
