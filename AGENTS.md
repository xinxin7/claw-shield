# AGENTS.md — For AI Agents Working on This Codebase

> This file is written for you, the AI agent. It describes the Claw Shield project structure, conventions, and how to make effective changes.

## What Is Claw Shield

Claw Shield is an AI agent governance infrastructure. It sits between agents and model providers, providing:

1. **Privacy routing** via OHTTP (Oblivious HTTP) relay-gateway architecture
2. **Real-time telemetry** — captures chain-of-thought reasoning, tool call decisions, and execution results
3. **A hosted dashboard** for visualizing agent behavior as a reasoning-to-action waterfall

## Architecture (Three Components)

### `client/` — OpenClaw Plugin (TypeScript)

- Entry point: `client/index.ts` → registers `ClawShieldPlugin`
- Core logic: `client/src/ohttp-shield.plugin.ts`
- Intercepts outbound model requests, wraps in OHTTP, injects `x-claw-shield-project-id` and `x-claw-shield-session-id` headers
- Session ID rotates on new user prompts; persists across tool-result continuations within one agent turn
- Project ID is auto-generated UUID, persisted at `~/.openclaw/plugins/claw-shield/.project-id`
- Dependencies: `bhttp-js`, `ohttp-js`

### `relay/` — Cloudflare Worker (JavaScript)

- Simple pass-through relay (`relay/index.js`)
- Sees the client's IP but never decrypts the OHTTP payload
- Deployed via `wrangler deploy` from `relay/`

### `gateway/` — Cloudflare Worker (Rust/WASM)

- Entry: `gateway/src/lib.rs` — OHTTP decryption, request routing, telemetry orchestration
- Telemetry: `gateway/src/telemetry.rs` — SSE parsing for OpenAI/Anthropic/Gemini, CoT extraction, tool call logging, D1 storage
- Dashboard: `gateway/src/dashboard.html` — single-page app embedded via `include_str!()`, served at `/dashboard`
- D1 database `TELEMETRY_DB` stores trace records in a `traces` table indexed by `(project_id, timestamp_ms)`
- Migrations live in `gateway/migrations/` — apply with `npx wrangler d1 migrations apply claw-shield-telemetry`
- KV namespace `WAITLIST` is used only for the waitlist feature (low-volume, read-heavy)
- API endpoints: `GET /api/traces?project=X`, `GET /api/summary?project=X`
- Built with `worker-build --release`, deployed via `wrangler deploy` from `gateway/`

## Key Conventions

- **Language**: All code comments, UI text, and documentation are in English
- **Dashboard styling**: CSS custom properties defined in `:root` of `dashboard.html`. Design is dark-mode with Inter + JetBrains Mono fonts
- **Telemetry data model**: `TraceRecord` in `telemetry.rs` is the canonical schema — any new fields must be added there, to the D1 migration, and to `store_trace` / `list_traces`
- **Provider SSE parsing**: Each provider (OpenAI, Anthropic, Google) has its own `parse_*_sse` and `parse_*_json` function in `telemetry.rs`
- **Sensitivity detection**: `detect_sensitivity()` in `telemetry.rs` flags dangerous tool names and content patterns
- **No client-side telemetry storage**: All telemetry lives on the gateway D1 database. The client only injects identity headers

## How to Add a New Provider

1. Add the provider's base URL to `providerTargets` in `client/openclaw.plugin.json`
2. Add SSE/JSON parsing functions in `gateway/src/telemetry.rs` (follow the `parse_openai_sse` pattern)
3. Update `infer_provider_from_url()` in `telemetry.rs`
4. Add to the Providers table in `README.md`

## How to Add a New Dashboard Feature

1. Modify `gateway/src/dashboard.html` — it's a self-contained SPA (HTML + CSS + JS in one file)
2. Data comes from `mergeSession()` which aggregates traces within a session
3. The waterfall uses a row-based grid layout: each `wf-row` is a `1fr 200px 1fr` grid with CoT / Decision / Output cells
4. After changes, deploy with `npx wrangler deploy` from `gateway/`

## How to Add a New Gateway API Endpoint

1. Add the route match in the `fetch` handler in `gateway/src/lib.rs` (follow the `/api/traces` pattern)
2. Add CORS headers via `with_cors()`
3. D1 queries use `env.d1("TELEMETRY_DB")`

## Build & Deploy

```bash
# Gateway — first-time D1 setup
cd gateway
npx wrangler d1 create claw-shield-telemetry   # note the database_id in output
# paste database_id into wrangler.toml → [[d1_databases]] → database_id
npx wrangler d1 migrations apply claw-shield-telemetry

# Gateway (Rust → WASM)
cd gateway && npx wrangler deploy

# Relay
cd relay && npx wrangler deploy

# Client (install to OpenClaw)
cp -r client ~/.openclaw/extensions/claw-shield
cd ~/.openclaw/extensions/claw-shield && npm install --omit=dev
systemctl --user restart openclaw-gateway.service
```

## Testing

- Gateway dashboard: `https://claw-shield-gateway.ohttp.workers.dev/dashboard?project=YOUR_PROJECT_ID`
- Client status: `curl http://127.0.0.1:18789/api/plugins/claw-shield/status`
- Trigger telemetry: send any prompt through OpenClaw, then check the dashboard
