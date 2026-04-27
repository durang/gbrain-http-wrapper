/**
 * gbrain-http-wrapper — HTTP front-end for `gbrain serve` (stdio MCP).
 *
 * Endpoints:
 *   GET  /health            — liveness check (no auth)
 *   POST /mcp               — JSON-RPC request/response (Bearer required)
 *   GET  /mcp/sse           — Server-Sent Events stream (Bearer required)
 *
 * Auth: `Authorization: Bearer gbrain_<token>` validated against the same
 *       mcp_tokens table that `gbrain auth create` populates.
 *
 * Recursion guard: requests inherit `GBRAIN_HOOK_RUNNING=1` so child claude -p
 *       calls (if any) won't trigger Stop hooks recursively.
 */

import { Hono } from 'hono';
import { stream } from 'hono/streaming';
import { initPool, callMcp, poolStatus, shutdownPool } from './stdio-pool.ts';
import { validateToken, shutdownAuth } from './auth.ts';

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
const VERSION = '0.1.0';
const STARTED_AT = new Date().toISOString();

initPool();

const app = new Hono();

// ── Middleware: extract + validate Bearer ────────
async function requireAuth(c: any) {
  const header = c.req.header('Authorization') || '';
  const match = header.match(/^Bearer\s+(\S+)$/);
  if (!match) {
    return c.json({ error: 'missing_auth', detail: 'Bearer token required' }, 401);
  }
  const result = await validateToken(match[1]);
  if (!result.ok) {
    return c.json({ error: 'invalid_auth', detail: result.error }, 401);
  }
  c.set('tokenName', result.name);
  return null;
}

// ── GET /health (no auth) ────────────────────────
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    version: VERSION,
    started_at: STARTED_AT,
    uptime_sec: Math.floor((Date.now() - new Date(STARTED_AT).getTime()) / 1000),
    pool: poolStatus(),
  });
});

// JSON-RPC handler — registered at both `/` and `/mcp` so the wrapper works
// behind a Tailscale Funnel that strips the /mcp prefix AND when accessed
// directly on http://127.0.0.1:8787/mcp.
const handleRpc = async (c: any) => {
  const denial = await requireAuth(c);
  if (denial) return denial;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'bad_json' }, 400);
  }
  if (!body || typeof body !== 'object' || body.jsonrpc !== '2.0') {
    return c.json({ error: 'invalid_jsonrpc' }, 400);
  }

  const t0 = Date.now();
  try {
    const response = await callMcp(body);
    const elapsed = Date.now() - t0;
    console.error(`[mcp] ${c.get('tokenName')} ${body.method || '?'} ${elapsed}ms`);
    return c.json(response);
  } catch (e: any) {
    return c.json({
      jsonrpc: '2.0',
      id: body.id ?? null,
      error: { code: -32603, message: 'internal_error', data: e.message },
    }, 500);
  }
};
app.post('/', handleRpc);
app.post('/mcp', handleRpc);

// SSE handler — same dual mounting (root + /mcp/sse)
const handleSse = async (c: any) => {
  const denial = await requireAuth(c);
  if (denial) return denial;

  return stream(c, async (sw) => {
    sw.writeSSE = sw.writeSSE || (async (event: any) => {
      await sw.write(`data: ${JSON.stringify(event)}\n\n`);
    });

    // Send initial endpoint event
    await sw.writeSSE({ type: 'endpoint', url: '/mcp' });

    // Heartbeat every 15s — keep connection alive through proxies
    const heartbeat = setInterval(() => {
      sw.write(`: heartbeat ${Date.now()}\n\n`).catch(() => clearInterval(heartbeat));
    }, 15_000);

    // Hold the stream open; clients post messages to /mcp and we don't proactively
    // push (this is the "request-response over SSE" pattern, not server-push).
    // The connection closes when the client disconnects.
    await new Promise<void>((resolve) => {
      c.req.raw.signal?.addEventListener('abort', () => {
        clearInterval(heartbeat);
        resolve();
      });
    });
  });
};
app.get('/sse', handleSse);
app.get('/mcp/sse', handleSse);

// ── Boot ─────────────────────────────────────────
console.error(`[server] listening on http://${HOST}:${PORT}`);
console.error(`[server] version ${VERSION}, started ${STARTED_AT}`);

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  fetch: app.fetch,
});

process.on('SIGINT', async () => {
  console.error('[server] shutting down...');
  server.stop();
  shutdownPool();
  await shutdownAuth();
  process.exit(0);
});
process.on('SIGTERM', async () => {
  console.error('[server] SIGTERM received, shutting down...');
  server.stop();
  shutdownPool();
  await shutdownAuth();
  process.exit(0);
});
