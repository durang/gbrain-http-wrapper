/**
 * OAuth 2.1 implementation for gbrain-http-wrapper.
 *
 * Implements:
 *   - /.well-known/oauth-protected-resource  (RFC 9728)
 *   - /.well-known/oauth-authorization-server (RFC 8414)
 *   - /oauth/register  Dynamic Client Registration (RFC 7591)
 *   - /oauth/authorize Authorization endpoint with PKCE + master password consent
 *   - /oauth/token     Token endpoint (authorization_code + refresh_token grants)
 *
 * Single-user master-password gate: the user enters GBRAIN_OAUTH_PASSWORD on the
 * consent screen. Approved → generates auth code, redirects back. Rejected → error.
 *
 * Tokens issued via OAuth land in the same `access_tokens` table the rest of the
 * wrapper validates against, so OAuth and CLI-issued tokens share infrastructure.
 */

import { Hono } from 'hono';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL || process.env.GBRAIN_DATABASE_URL!;
const BASE_URL = (process.env.WRAPPER_BASE_URL || '').replace(/\/$/, '');
const OAUTH_PASSWORD = process.env.GBRAIN_OAUTH_PASSWORD || '';
// Tailscale Funnel mounts the wrapper at /mcp and STRIPS that prefix before
// forwarding to upstream. So all OAuth endpoints we advertise are /mcp-prefixed
// from the client's perspective; internally Hono routes them under root because
// that's what the wrapper actually receives after strip.
const ISSUER = (BASE_URL ? `${BASE_URL}/mcp` : 'https://localhost/mcp');

const sql = postgres(DATABASE_URL, { prepare: false });

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const sha256Buf = (s: string) => createHash('sha256').update(s).digest();
const b64url = (b: Buffer) => b.toString('base64url');
const randomToken = (bytes = 32) => 'gbrain_' + randomBytes(bytes).toString('hex');
const randomId = () => randomBytes(16).toString('hex');

// PKCE S256 verifier
function pkceMatches(verifier: string, challenge: string): boolean {
  return b64url(sha256Buf(verifier)) === challenge;
}

// Constant-time string compare (prevents timing attacks on password)
function constEq(a: string, b: string): boolean {
  const A = Buffer.from(a);
  const B = Buffer.from(b);
  if (A.length !== B.length) return false;
  return timingSafeEqual(A, B);
}

// ─── Discovery metadata ────────────────────────────
const RESOURCE_URL = ISSUER; // resource and issuer are same in our setup (MCP endpoint == OAuth server)

const protectedResourceMetadata = () => ({
  resource: RESOURCE_URL,
  authorization_servers: [ISSUER],
  bearer_methods_supported: ['header'],
  scopes_supported: ['mcp'],
  resource_documentation: 'https://github.com/durang/gbrain-http-wrapper',
});

const authServerMetadata = () => ({
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth/authorize`,
  token_endpoint: `${ISSUER}/oauth/token`,
  registration_endpoint: `${ISSUER}/oauth/register`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
  scopes_supported: ['mcp'],
});

// ─── DB ops ────────────────────────────────────────
async function registerClient(input: {
  client_name: string;
  redirect_uris: string[];
  software_id?: string;
  software_version?: string;
  token_endpoint_auth_method?: string;
}) {
  const client_id = randomId();
  let client_secret: string | null = null;
  let client_secret_hash: string | null = null;
  if (input.token_endpoint_auth_method === 'client_secret_post' || input.token_endpoint_auth_method === 'client_secret_basic') {
    client_secret = randomBytes(32).toString('hex');
    client_secret_hash = sha256(client_secret);
  }
  await sql`
    INSERT INTO oauth_clients (
      client_id, client_secret_hash, client_name, redirect_uris,
      token_endpoint_auth_method, software_id, software_version
    ) VALUES (
      ${client_id}, ${client_secret_hash}, ${input.client_name}, ${input.redirect_uris},
      ${input.token_endpoint_auth_method || 'none'}, ${input.software_id || null}, ${input.software_version || null}
    )
  `;
  return { client_id, client_secret };
}

async function getClient(client_id: string) {
  const rows = await sql<any[]>`
    SELECT client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method
    FROM oauth_clients WHERE client_id = ${client_id} LIMIT 1
  `;
  return rows[0] || null;
}

async function storeAuthCode(input: {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
}): Promise<string> {
  const code = randomBytes(32).toString('base64url');
  const code_hash = sha256(code);
  const expires_at = new Date(Date.now() + 10 * 60 * 1000); // 10 min
  await sql`
    INSERT INTO oauth_codes (
      code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at
    ) VALUES (
      ${code_hash}, ${input.client_id}, ${input.redirect_uri}, ${input.code_challenge},
      ${input.code_challenge_method}, ${input.scope}, ${expires_at}
    )
  `;
  return code;
}

async function consumeAuthCode(code: string) {
  const code_hash = sha256(code);
  const rows = await sql<any[]>`
    SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used_at
    FROM oauth_codes WHERE code_hash = ${code_hash} LIMIT 1
  `;
  if (!rows.length) return null;
  const r = rows[0];
  if (r.used_at) return { error: 'code_used' };
  if (new Date(r.expires_at) < new Date()) return { error: 'code_expired' };
  await sql`UPDATE oauth_codes SET used_at = NOW() WHERE code_hash = ${code_hash}`;
  return r;
}

async function issueAccessToken(client_id: string, scope: string) {
  const token = randomToken(32);
  const token_hash = sha256(token);
  const name = `oauth/${client_id}/${Date.now()}`;
  await sql`
    INSERT INTO access_tokens (name, token_hash) VALUES (${name}, ${token_hash})
  `;
  return { access_token: token, name };
}

async function issueRefreshToken(client_id: string, access_token_name: string, scope: string) {
  const refresh = 'gbrain_refresh_' + randomBytes(32).toString('hex');
  const refresh_hash = sha256(refresh);
  const expires_at = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  await sql`
    INSERT INTO oauth_refresh_tokens (refresh_hash, client_id, access_token_name, scope, expires_at)
    VALUES (${refresh_hash}, ${client_id}, ${access_token_name}, ${scope}, ${expires_at})
  `;
  return refresh;
}

async function consumeRefreshToken(refresh: string) {
  const refresh_hash = sha256(refresh);
  const rows = await sql<any[]>`
    SELECT client_id, scope, expires_at, revoked_at
    FROM oauth_refresh_tokens WHERE refresh_hash = ${refresh_hash} LIMIT 1
  `;
  if (!rows.length) return null;
  const r = rows[0];
  if (r.revoked_at) return { error: 'revoked' };
  if (new Date(r.expires_at) < new Date()) return { error: 'expired' };
  return r;
}

// ─── Hono router ───────────────────────────────────
export const oauthRouter = new Hono();

// Discovery — OAuth 2.1 (RFC 9728 + RFC 8414)
oauthRouter.get('/.well-known/oauth-protected-resource', (c) => c.json(protectedResourceMetadata()));
oauthRouter.get('/.well-known/oauth-protected-resource/mcp', (c) => c.json(protectedResourceMetadata()));
oauthRouter.get('/.well-known/oauth-authorization-server', (c) => c.json(authServerMetadata()));

// Discovery — OpenID Connect Discovery 1.0 (some clients including claude.ai
// probe this endpoint). We return the OAuth metadata supplemented with the
// minimum OIDC required fields, declaring we don't issue id_tokens. This is
// enough to satisfy clients that fall through to oauth flows.
oauthRouter.get('/.well-known/openid-configuration', (c) => c.json({
  ...authServerMetadata(),
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['none'],
  // We do not implement id_tokens; clients should use access_token only.
  // userinfo_endpoint absent on purpose — we don't have user identity beyond
  // the master-password approval gate.
}));

// Dynamic Client Registration (RFC 7591)
oauthRouter.post('/oauth/register', async (c) => {
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_client_metadata' }, 400); }
  const redirect_uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (redirect_uris.length === 0) {
    return c.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris required' }, 400);
  }
  const client_name = body.client_name || 'unnamed-client';
  const auth_method = body.token_endpoint_auth_method || 'none';
  const reg = await registerClient({
    client_name,
    redirect_uris,
    software_id: body.software_id,
    software_version: body.software_version,
    token_endpoint_auth_method: auth_method,
  });
  const out: any = {
    client_id: reg.client_id,
    client_name,
    redirect_uris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: auth_method,
  };
  if (reg.client_secret) out.client_secret = reg.client_secret;
  return c.json(out, 201);
});

// Authorization endpoint — shows consent form, validates password, issues code
oauthRouter.get('/oauth/authorize', async (c) => {
  const params = c.req.query();
  const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state, scope } = params;
  if (response_type !== 'code') return c.json({ error: 'unsupported_response_type' }, 400);
  if (!client_id || !redirect_uri || !code_challenge) {
    return c.json({ error: 'invalid_request', error_description: 'missing required params' }, 400);
  }
  const client = await getClient(client_id);
  if (!client) return c.json({ error: 'invalid_client' }, 400);
  if (!client.redirect_uris.includes(redirect_uri)) {
    return c.json({ error: 'invalid_redirect_uri' }, 400);
  }
  if ((code_challenge_method || 'plain') !== 'S256') {
    return c.json({ error: 'invalid_request', error_description: 'PKCE S256 required' }, 400);
  }

  const consentForm = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Approve GBrain access</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;background:#0a0a0a;color:#e5e5e5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:36px;max-width:480px;width:100%}
h1{font-size:22px;margin:0 0 8px;color:#fff}
.client{font-weight:600;color:#f97316}
p{color:#a3a3a3;margin:8px 0}
ul{color:#a3a3a3;font-size:14px}
input[type=password]{width:100%;padding:12px;background:#0a0a0a;border:1px solid #2a2a2a;border-radius:8px;color:#e5e5e5;font-size:16px;margin:12px 0}
input[type=password]:focus{outline:none;border-color:#f97316}
.btn{display:block;width:100%;padding:12px;background:#f97316;color:#000;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;margin-top:16px}
.btn:hover{background:#fb923c}
.error{color:#ef4444;font-size:14px;margin:8px 0}
.tiny{color:#525252;font-size:12px;margin-top:24px}
</style></head><body>
<form class="card" method="POST" action="${ISSUER}/oauth/authorize">
<h1>Approve <span class="client">${escapeHtml(client.client_name)}</span> access</h1>
<p>This app wants to read and write to your GBrain.</p>
<ul>
  <li>Search and read pages</li>
  <li>Create and update pages</li>
  <li>Manage links and timeline entries</li>
</ul>
<p>Enter your master password to approve:</p>
<input type="password" name="password" autofocus required placeholder="GBRAIN_OAUTH_PASSWORD"/>
${params.error ? `<div class="error">${escapeHtml(String(params.error))}</div>` : ''}
<input type="hidden" name="client_id" value="${escapeHtml(client_id)}"/>
<input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}"/>
<input type="hidden" name="response_type" value="code"/>
<input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}"/>
<input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method || 'S256')}"/>
<input type="hidden" name="state" value="${escapeHtml(state || '')}"/>
<input type="hidden" name="scope" value="${escapeHtml(scope || 'mcp')}"/>
<button class="btn" type="submit">Approve</button>
<div class="tiny">Powered by gbrain-http-wrapper · Single-user OAuth 2.1</div>
</form></body></html>`;
  return c.html(consentForm);
});

oauthRouter.post('/oauth/authorize', async (c) => {
  const form = await c.req.parseBody();
  const password = String(form.password || '');
  const client_id = String(form.client_id || '');
  const redirect_uri = String(form.redirect_uri || '');
  const code_challenge = String(form.code_challenge || '');
  const code_challenge_method = String(form.code_challenge_method || 'S256');
  const state = String(form.state || '');
  const scope = String(form.scope || 'mcp');

  if (!OAUTH_PASSWORD) {
    return c.text('GBRAIN_OAUTH_PASSWORD not configured on server', 500);
  }
  if (!constEq(password, OAUTH_PASSWORD)) {
    // Re-render form with error (uses GET endpoint at the public /mcp-prefixed URL)
    const url = new URL(`${ISSUER}/oauth/authorize`);
    url.searchParams.set('client_id', client_id);
    url.searchParams.set('redirect_uri', redirect_uri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('code_challenge', code_challenge);
    url.searchParams.set('code_challenge_method', code_challenge_method);
    if (state) url.searchParams.set('state', state);
    if (scope) url.searchParams.set('scope', scope);
    url.searchParams.set('error', 'Invalid password');
    return c.redirect(url.toString());
  }

  const code = await storeAuthCode({ client_id, redirect_uri, code_challenge, code_challenge_method, scope });
  const redirect = new URL(redirect_uri);
  redirect.searchParams.set('code', code);
  if (state) redirect.searchParams.set('state', state);
  return c.redirect(redirect.toString());
});

// Token endpoint
oauthRouter.post('/oauth/token', async (c) => {
  const form = await c.req.parseBody();
  const grant_type = String(form.grant_type || '');
  const client_id = String(form.client_id || '');

  if (grant_type === 'authorization_code') {
    const code = String(form.code || '');
    const redirect_uri = String(form.redirect_uri || '');
    const code_verifier = String(form.code_verifier || '');
    const consumed = await consumeAuthCode(code);
    if (!consumed) return c.json({ error: 'invalid_grant' }, 400);
    if (consumed.error) return c.json({ error: 'invalid_grant', error_description: consumed.error }, 400);
    if (consumed.client_id !== client_id) return c.json({ error: 'invalid_grant', error_description: 'client mismatch' }, 400);
    if (consumed.redirect_uri !== redirect_uri) return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
    if (!pkceMatches(code_verifier, consumed.code_challenge)) return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);

    const issued = await issueAccessToken(client_id, consumed.scope);
    const refresh = await issueRefreshToken(client_id, issued.name, consumed.scope);
    return c.json({
      access_token: issued.access_token,
      token_type: 'Bearer',
      expires_in: 3600 * 24 * 7, // 7 days
      refresh_token: refresh,
      scope: consumed.scope,
    });
  }

  if (grant_type === 'refresh_token') {
    const refresh_token = String(form.refresh_token || '');
    const r = await consumeRefreshToken(refresh_token);
    if (!r) return c.json({ error: 'invalid_grant' }, 400);
    if (r.error) return c.json({ error: 'invalid_grant', error_description: r.error }, 400);
    if (r.client_id !== client_id) return c.json({ error: 'invalid_grant', error_description: 'client mismatch' }, 400);
    const issued = await issueAccessToken(client_id, r.scope);
    return c.json({
      access_token: issued.access_token,
      token_type: 'Bearer',
      expires_in: 3600 * 24 * 7,
      scope: r.scope,
    });
  }

  return c.json({ error: 'unsupported_grant_type' }, 400);
});

// HTML escape helper
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]!));
}

export async function shutdownOauth() {
  await sql.end({ timeout: 5 });
}
