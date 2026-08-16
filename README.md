# dsh-plugin-acp

[Agentic Control Plane](https://agenticcontrolplane.com) for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness): every tool call is checked against your policies before it runs, and every decision is recorded — what ran, what was blocked, and why.

This is a native Cordis plugin on dsh's typed interception points, not a shell-hook shim. It registers on:

- `tools/pre-execute` — the policy decision. `allow` lets the call through, `deny` blocks it with the reason in the trajectory, `ask` hands off to dsh's own approval flow.
- `tools/post-execute` — output scanning. A server-side block turns the result into corrective feedback; shadow-mode notices surface what enforcement *would* have done.

## Install

```sh
curl -sf https://agenticcontrolplane.com/install.sh | bash
```

That detects dsh, installs this plugin into every profile you have, opens your
browser once to sign in, and saves the key to `~/.acp/credentials` — which the
plugin reads on its own. There is no token to copy and nothing to export.

<details>
<summary>Manual install</summary>

```sh
dsh plugin --profile <your-profile> add dsh-plugin-acp
dsh --profile <your-profile>
```

Credentials come from `~/.acp/credentials` (written by the installer above) or
from `ACP_BEARER_TOKEN` if you would rather set it yourself — useful on a
headless box. Get a key at
[cloud.agenticcontrolplane.com](https://cloud.agenticcontrolplane.com).

Confirm the row actually mounted — installing the package and composing it into
the profile are two different things:

```sh
dsh --profile <your-profile> --dump-config | grep dsh-plugin-acp
```

If it isn't there, add `dsh-plugin-acp` to that profile's `package.json`
`"dsh.profile.bundles"` list.

</details>

No build step, no dependencies, plain ESM. Installing from git works too (`dsh plugin add github:agentic-control-plane/dsh-acp-plugin`) and needs no build allowance.

No key? The plugin says so loudly and stays out of the way — it never bricks a session.

## Configuration

Override the row in your profile's `cordis.patch.yml`:

```yaml
- id: acp
  name: dsh-plugin-acp
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

## Two things to know

- dsh's `packages/acp` is Zed's Agent Client Protocol — an unrelated project that shares an acronym. This plugin is the Agentic Control Plane.
- Already running our Claude Code hook? dsh's `@deepseek-ai/dsh-hooks-claude-code` bridge runs an unmodified `hooks.json`, so `govern.mjs` works today with zero new code — deny and ask are honored, but input rewriting is not. This native plugin is the recommended path.

## Test

```sh
npm test
```

MIT
