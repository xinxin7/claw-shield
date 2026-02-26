# Claw Shield

🛡️ Protect your OpenClaw traffic.

![Claw Shield Architecture](https://lh3.googleusercontent.com/gg-dl/AOI_d_9FmmROMe95IJOuBb9LuGZNprtpsGLMkP4STY6kucMi8yl_lZHspUarUnP8GGYPZ8zAGr1GYMIYnWVkF3J2QCpQCDd719Xg_bpNTvejcnKutic27AFGRigt7UD5XUmWaFQWrqDc9YwCjYcWhPxfeMy3SrorlvBk5iV_MNNoyIyTwBjOmA=s1024-rj)

Claw Shield routes model requests through an OHTTP `Relay -> Gateway` path, reducing provider-side fingerprinting while preserving the OpenClaw workflow you already use.

## Why Use Claw Shield ✨

- **Harder to profile**: providers see relayed traffic, not a direct OpenClaw fingerprint tied to your behavior.
- **Lower distillation-pressure exposure**: OHTTP + fingerprint reduction addresses risk patterns discussed in [Anthropic's distillation report](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks).
- **Less OpenClaw-targeted throttling**: lower chance of being labeled as obvious OpenClaw traffic and rate-limited aggressively like this [community report](https://www.reddit.com/r/AI_Agents/comments/1r70lq9/openclaw_broke_down_after_just_4_messages/).

## Providers 🚀

### ✅ Verified

- `google` (Gemini)
- `openai`

### 🧩 Supported

- `anthropic`
- `openrouter`
- `mistral`
- `groq`

> `Verified` means end-to-end tested in this repo's current release workflow.  
> `Supported` means implemented via `providerTargets` and compatible routing/auth logic.

## Quick Start

### Install (WSL/Linux)

```bash
bash -lc 'set -euo pipefail; EXT="$HOME/.openclaw/extensions/claw-shield"; rm -rf "$EXT"; mkdir -p "$HOME/.openclaw/extensions"; tmp="$(mktemp -d)"; git clone --depth 1 "https://github.com/xinxin7/claw-shield.git" "$tmp/claw-shield"; cp -r "$tmp/claw-shield/client" "$EXT"; (cd "$EXT" && npm install --omit=dev); systemctl --user restart openclaw-gateway.service; sleep 5; curl -sS "http://127.0.0.1:18789/api/plugins/claw-shield/status"'
```

### Install (macOS)

```bash
bash -lc 'set -euo pipefail; EXT="$HOME/.openclaw/extensions/claw-shield"; rm -rf "$EXT"; mkdir -p "$HOME/.openclaw/extensions"; tmp="$(mktemp -d)"; git clone --depth 1 "https://github.com/xinxin7/claw-shield.git" "$tmp/claw-shield"; cp -r "$tmp/claw-shield/client" "$EXT"; (cd "$EXT" && npm install --omit=dev); (command -v openclaw >/dev/null && openclaw gateway restart) || true; sleep 5; curl -sS "http://127.0.0.1:18789/api/plugins/claw-shield/status"'
```

### Verify protection

- `"ok": true`
- `"status": "You're protected"`

## Integrate with OpenClaw

- OpenClaw is installed and running locally.
- Model providers and credentials are configured in OpenClaw.
- Relay and Gateway are deployed and reachable.

## Repository Layout

- `client/` OpenClaw plugin (interception + OHTTP client behavior)
- `relay/` Cloudflare Worker relay
- `gateway/` Cloudflare Worker gateway

