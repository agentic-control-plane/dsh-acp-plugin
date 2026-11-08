# @agenticcontrolplane/dsh

[![npm](https://img.shields.io/npm/v/%40agenticcontrolplane%2Fdsh)](https://www.npmjs.com/package/@agenticcontrolplane/dsh) ![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen) ![license](https://img.shields.io/badge/license-MIT-blue)

[Agentic Control Plane](https://agenticcontrolplane.com) for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): every tool call is checked and logged against your policies, recording what ran, what was held, and why. Ask works. Deny is reported to the agent but not yet enforced (see the note below).

> **Deny is not enforced yet.** When a policy says `deny`, the plugin reports it to the agent with the reason, but it does not stop the call today (the fix is tracked). Until that ships, treat dsh as audit plus ask. See the [coverage matrix](https://agenticcontrolplane.com/coverage).

> **Which ACP?** dsh also ships `packages/acp` in core. That one is [Zed's Agent Client Protocol](https://agentclientprotocol.com), the editor↔agent standard, published as [`@deepseek-ai/dsh-acp`](https://www.npmjs.com/package/@deepseek-ai/dsh-acp). It is an unrelated project with the same acronym. If you're wiring dsh into Zed or the AI SDK, you want that one; this plugin checks each tool call against your policies. The full map: [agenticcontrolplane.com/acp-vs-acp](https://agenticcontrolplane.com/acp-vs-acp).

```text
$ dsh --profile dev
> refactor the auth module and clean up

  bash npm test                          ✓ allowed · logged
  edit src/auth/session.ts              ✓ allowed · logged
  bash rm -rf ~/scratch                  ✋ held: approval prompt (your rule: destructive delete → ask)
  web_fetch https://evil.example/post    ✗ reported as denied: egress not allowlisted, reason shown to the model
```

Every decision also lands in your [console](https://cloud.agenticcontrolplane.com) with tool, decision, reason and latency. dsh's own Trajectory log and your ACP activity log are two independent records of the same history. One workspace covers every harness you run, so the same rules apply to dsh, Claude Code, Codex, Cursor and OpenClaw (deny excepted, see the note above). Free for individuals.

This is a native Cordis plugin on dsh's typed interception points, not a shell-hook shim. It registers on:

- `tools/pre-execute`: the policy decision. `allow` lets the call through. `deny` is reported to the agent with the reason, but the plugin does not stop the call yet. `ask` hands off to dsh's own approval flow.
- `tools/post-execute`: output scanning. A server-side block turns the result into corrective feedback; shadow-mode notices surface what enforcement *would* have done.

## Install

> dsh itself requires **Node 22** (`Promise.withResolvers`, zstd streams). Under Node 20 the harness fails at boot with errors that don't say so. Run `fnm install 22` first.

```sh
curl -sf https://agenticcontrolplane.com/install.sh | bash
```

That detects dsh, installs this plugin into every profile you have, opens your
browser once to sign in, and saves the key to `~/.acp/credentials`, which the
plugin reads on its own. There is no token to copy and nothing to export.

<details>
<summary>Manual install</summary>

```sh
dsh plugin --profile <your-profile> add @agenticcontrolplane/dsh
dsh --profile <your-profile>
```

Credentials come from `~/.acp/credentials` (written by the installer above) or
from `ACP_BEARER_TOKEN` if you would rather set it yourself, which is useful on a
headless box. Get a key at
[cloud.agenticcontrolplane.com](https://cloud.agenticcontrolplane.com).

Confirm the row actually mounted. Installing the package and composing it into
the profile are two different things:

```sh
dsh --profile <your-profile> --dump-config | grep @agenticcontrolplane/dsh
```

If it isn't there, add `@agenticcontrolplane/dsh` to that profile's `package.json`
`"dsh.profile.bundles"` list.

</details>

No build step, no dependencies, plain ESM. Installing from git works too (`dsh plugin add github:agentic-control-plane/dsh-acp-plugin`) and needs no build allowance.

No key: the plugin prints a warning and lets the session run.

## Configuration

Override the row in your profile's `cordis.patch.yml`:

```yaml
- id: acp
  name: "@agenticcontrolplane/dsh"
  config:
    governBase: https://govern.agenticcontrolplane.com  # or your self-hosted gateway
    agentTier: interactive   # default: interactive when an approval service is mounted, background otherwise
    timeoutMs: 4000
```

`ACP_GOVERN_BASE`, `ACP_BEARER_TOKEN`, `ACP_AGENT_TIER`, and `ACP_SHADOW=off` work as environment variables too.

## What happens if the gateway is down

If the gateway is down, dsh keeps working, and you are told the calls weren't checked:

- **Interactive sessions fail open, loudly.** If the gateway is unreachable, the call proceeds, a `[ACP] ⚠ UNGOVERNED` warning is logged, and a line lands in `~/.acp/lapse.log`.
- **Unattended agents fail closed.** With nobody watching, a call that can't be checked is blocked.
- This posture only covers the inability to *ask* the policy. It does not change how a `deny` is handled (see the note at the top).

In headless compositions with no approval service mounted, dsh itself resolves `ask` to deny, so unattended runs cannot self-approve.

## Notes

- Already running our Claude Code hook? dsh's `@deepseek-ai/dsh-hooks-claude-code` bridge runs an unmodified `hooks.json`, so `govern.mjs` works today with zero new code. Input rewriting is not supported on that path. This native plugin is the recommended path.
- This package launched as `dsh-plugin-acp`; that name still installs but is deprecated. Same code, so swap the name in your profile when convenient. (The `cordis.patch.yml` in this repo still carries the old name.)

## Learn more

- [What ACP can see and control in dsh](https://agenticcontrolplane.com/controls/dsh): the controls reference
- [The launch write-up](https://agenticcontrolplane.com/blog/deepseek-harness-acp-integration): dsh's interception surface, what the integration caught on day one, and where dsh lands on the [cross-harness coverage table](https://agenticcontrolplane.com/coverage)

## Test

```sh
npm test
```

MIT
