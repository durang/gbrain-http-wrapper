# gbrain-http-wrapper

OAuth 2.1 + Bearer HTTP front-end for `gbrain serve` (stdio MCP). Lets non-stdio clients — **Claude Desktop**, **Claude.ai web** (Cowork), mobile, Perplexity, custom apps — read and write to the same GBrain backend that local Claude Code uses via stdio.

> **Status:** Phase 4C connected. Claude Desktop ✅ and Claude.ai web ✅ both authenticate against this wrapper in production.

## Architecture

```
HTTP client (OAuth 2.1 or static Bearer)
   │
   ▼ POST /mcp { jsonrpc: "2.0", method: "tools/call", ... }
this server (Bun + Hono :8787)
   ├─ /.well-known/* + /oauth/* — OAuth 2.1 (PKCE + DCR + refresh)
   ├─ validates Bearer against access_tokens table
   ├─ routes JSON-RPC to one of N pre-warm `gbrain serve` children
   ├─ pipes the response back as JSON
   └─ /mcp/sse for SSE streaming clients
   │
   ▼ stdin/stdout
gbrain serve (stdio MCP)
   │
   ▼ DATABASE_URL
Supabase Postgres (the brain)
```

Tailscale Funnel mounts the wrapper at `/mcp` and **strips that prefix** before forwarding to the upstream. The wrapper therefore dual-mounts every route under both `/` and `/mcp` so that `https://your-machine.ts.net/mcp/...` works whether the prefix survives or not.

## Endpoints

### MCP (JSON-RPC over HTTP)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness + pool status (for tunnel pings) |
| `POST` | `/` and `/mcp` | Bearer | Standard JSON-RPC request/response |
| `GET` | `/` and `/mcp` | Bearer | MCP Streamable HTTP GET handler |
| `GET` | `/sse` and `/mcp/sse` | Bearer | Server-Sent Events stream (heartbeat every 15s) |
| `OPTIONS` | any | none | CORS preflight |

### OAuth 2.1 (RFC 6749 + 7591 + 8414 + 9728 + PKCE)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/oauth-protected-resource` | RFC 9728 — resource metadata |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 — auth server metadata |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery alias |
| `POST` | `/oauth/register` | RFC 7591 — Dynamic Client Registration |
| `GET` | `/oauth/authorize` | Authorization endpoint (PKCE S256 + master-password consent screen) |
| `POST` | `/oauth/token` | Token endpoint — `authorization_code` + `refresh_token` grants |

All of the above are also reachable under the `/mcp` prefix for Tailscale Funnel compatibility.

## Auth — two paths

Both paths produce a token in the same `access_tokens` table (SHA-256 hashed at rest, cached 60s in-memory).

### 1. Static Bearer (Claude Desktop, scripts, mobile)

```bash
cd /home/ec2-user/gbrain
bun run src/commands/auth.ts create "claude-desktop-mac"
# → prints: gbrain_<64-hex>  (save this; not shown again)
```

Use it:

```
Authorization: Bearer gbrain_<64-hex>
```

Revoke:

```bash
bun run src/commands/auth.ts revoke "claude-desktop-mac"
```

### 2. OAuth 2.1 with PKCE + DCR (Claude.ai web)

Claude.ai web cannot accept a static token paste — it requires the full OAuth 2.1 dance. The wrapper implements:

- **Dynamic Client Registration** — clients self-register at `/oauth/register`, no pre-shared client_id needed.
- **PKCE S256** — verifier hashed and bound to the auth code.
- **Master-password consent screen** — single-user gate (`GBRAIN_OAUTH_PASSWORD`), constant-time compared.
- **Refresh tokens** — long-lived sessions without re-consent.

The client is pointed at `https://your-machine.ts.net/mcp` and discovers everything else via the well-known metadata.

## Configuration

`.env` (mode 600):

```
DATABASE_URL=postgresql://...
PORT=8787
HOST=127.0.0.1
GBRAIN_BIN=/home/ec2-user/.bun/bin/gbrain
GBRAIN_POOL_SIZE=3
GBRAIN_HOOK_RUNNING=1

# OAuth 2.1
WRAPPER_BASE_URL=https://your-machine.ts.net
GBRAIN_OAUTH_PASSWORD=<long-random-string>
```

- `WRAPPER_BASE_URL` — public origin used to advertise OAuth endpoints in discovery metadata. The wrapper appends `/mcp` internally to match the Tailscale Funnel mount.
- `GBRAIN_OAUTH_PASSWORD` — single-user master password shown on the consent screen. Use a long random value.
- `GBRAIN_HOOK_RUNNING=1` — prevents recursive Stop-hook triggers from any `claude -p` call inside a `gbrain serve` child.

## Run

Foreground (dev):

```bash
cd /home/ec2-user/gbrain-http-wrapper
set -a && . .env && set +a
bun run src/server.ts
```

Production (systemd):

```bash
sudo cp systemd/gbrain-http-wrapper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gbrain-http-wrapper
sudo systemctl status gbrain-http-wrapper
journalctl -u gbrain-http-wrapper -f
```

## Smoke test

```bash
TOKEN=$(cd /home/ec2-user/gbrain && bun run src/commands/auth.ts create "smoke" 2>&1 | grep -oE 'gbrain_[a-f0-9]+')

# Health (no auth)
curl http://127.0.0.1:8787/health

# Reject without Bearer
curl -X POST http://127.0.0.1:8787/mcp -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# → 401 missing_auth

# List tools
curl -X POST http://127.0.0.1:8787/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# → 41 tools

# OAuth discovery
curl https://your-machine.ts.net/mcp/.well-known/oauth-authorization-server | jq

# Cleanup
cd /home/ec2-user/gbrain && bun run src/commands/auth.ts revoke "smoke"
```

## Public exposure

Once healthy on `127.0.0.1:8787`, expose via Tailscale Funnel:

```bash
tailscale funnel --bg --set-path /mcp 8787
```

Both share `https://your-machine.ts.net/`:

- **Claude Desktop** → URL `https://your-machine.ts.net/mcp` + static Bearer token.
- **Claude.ai web** → "Add custom MCP server" → URL `https://your-machine.ts.net/mcp` → triggers OAuth flow → master-password consent → connected.

## Design notes

- **Pool of N children**: spawning `gbrain serve` takes 200–500ms. Pool of `GBRAIN_POOL_SIZE` (default 3) keeps children warm so each request only pays the JSON-RPC roundtrip (~50ms).
- **Per-child serialization**: each child handles one request at a time; pool acquire/release queues additional requests.
- **Auto-respawn**: if a child exits (crash, OOM, etc.), the pool spawns a replacement after 1s.
- **Token cache**: valid tokens cached for 60s; revocations propagate within 60s.
- **MCP notifications**: fire-and-forget — the wrapper does not wait for a response when the JSON-RPC payload has no `id`.
- **CORS**: full preflight + permissive headers so browser-based clients (Claude.ai web) can connect.
- **Dual-mount**: every route is registered under both `/` and `/mcp` so the same binary works whether Tailscale Funnel strips the prefix or not.
- **PgBouncer-safe**: `prepare: false` on the postgres client (gbrain convention).

## Status

| Phase | Status |
|---|---|
| 4A — wrapper local + smoke test | ✅ Validated |
| 4B — Tailscale Funnel + per-client tokens | ✅ Done |
| 4C — Claude Desktop + Claude.ai web connected | ✅ Done |
| 4D — Upstream PR as `gbrain serve --http` | 🔜 Future |
