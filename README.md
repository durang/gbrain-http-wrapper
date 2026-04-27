# gbrain-http-wrapper

HTTP front-end for `gbrain serve` (stdio MCP). Lets non-stdio clients (Claude Desktop, claude.ai web Cowork, mobile, Perplexity, custom apps) read and write to the same GBrain backend that local Claude Code uses via stdio.

## Architecture

```
HTTP client (Bearer auth)
   │
   ▼ POST /mcp { jsonrpc: "2.0", method: "tools/call", ... }
this server (Bun + Hono :8787)
   ├─ validates Bearer against access_tokens table
   ├─ routes JSON-RPC to one of 3 pre-warm `gbrain serve` children
   ├─ pipes the response back as JSON
   └─ /mcp/sse for SSE streaming clients
   │
   ▼ stdin/stdout
gbrain serve (stdio MCP)
   │
   ▼ DATABASE_URL
Supabase Postgres (the brain)
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness + pool status (for tunnel pings) |
| POST | `/mcp` | Bearer | Standard JSON-RPC request/response |
| GET | `/mcp/sse` | Bearer | Server-Sent Events stream (heartbeat every 15s) |

## Auth

Tokens come from `gbrain auth create <name>`:

```bash
cd /home/ec2-user/gbrain
bun run src/commands/auth.ts create "claude-desktop-mac"
# → prints: gbrain_<64-hex>  (save this; not shown again)
```

Use it with HTTP clients:

```
Authorization: Bearer gbrain_<64-hex>
```

Tokens are stored hashed (SHA-256) in `access_tokens`. Revoke with:

```bash
bun run src/commands/auth.ts revoke "claude-desktop-mac"
```

The wrapper caches valid tokens for 60s in-memory to reduce DB hits; revocation takes up to 60s to propagate.

## Configuration

`.env` (mode 600):

```
DATABASE_URL=postgresql://...
PORT=8787
HOST=127.0.0.1
GBRAIN_BIN=/home/ec2-user/.bun/bin/gbrain
GBRAIN_POOL_SIZE=3
GBRAIN_HOOK_RUNNING=1
```

`GBRAIN_HOOK_RUNNING=1` is set so any `claude -p` call from inside a `gbrain serve` child will not recursively trigger Stop hooks.

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

# Cleanup
cd /home/ec2-user/gbrain && bun run src/commands/auth.ts revoke "smoke"
```

## Public exposure (Phase 4B)

Once the wrapper is healthy on `127.0.0.1:8787`, expose it publicly via Tailscale Funnel:

```bash
tailscale funnel --bg --set-path /mcp 8787
```

This adds path `/mcp` on top of the existing OpenClaw Tailscale serve at `/`, so both share `https://your-machine.ts.net/`.

After that, any HTTP client (Claude Desktop, claude.ai web, mobile) can connect by giving them:

- URL: `https://your-machine.ts.net/mcp`
- Bearer token: per-client, revocable

## Design notes

- **Pool of 3 children**: spawning `gbrain serve` takes 200-500ms. The pool keeps 3 ready so each request only pays the JSON-RPC roundtrip (~50ms).
- **Per-child serialization**: each child handles one request at a time; pool acquire/release queues additional requests.
- **Auto-respawn**: if a child exits (crash, OOM, etc.), the pool spawns a replacement after 1s.
- **Cache**: valid tokens cached for 60s; revoked tokens take up to 60s to propagate.
- **PgBouncer-safe**: `prepare: false` on the postgres client (gbrain convention).

## Status

| Phase | Status |
|---|---|
| 4A — wrapper local + smoke test | ✅ Validated |
| 4B — Tailscale Funnel + per-client tokens | ⏳ Next |
| 4C — Claude Desktop + claude.ai connected | ⏳ |
| 4D — Upstream PR as `gbrain serve --http` | 🔜 Future |
