/**
 * Bearer token validation against the same token table that `gbrain auth` populates.
 *
 * Tokens are stored hashed (SHA-256) in the `access_tokens` table. We hash the incoming
 * token and check for a non-revoked row. The plaintext token is never logged.
 *
 * Schema (created by gbrain v0.18+ migrations):
 *   access_tokens (id, name, token_hash, created_at, last_used_at, revoked_at)
 */

import { createHash } from 'crypto';
import postgres from 'postgres';

const DATABASE_URL = process.env.DATABASE_URL || process.env.GBRAIN_DATABASE_URL;
if (!DATABASE_URL) {
  console.error('[auth] DATABASE_URL or GBRAIN_DATABASE_URL must be set');
  process.exit(1);
}

// Disable prepared statements to play nice with PgBouncer transaction pooling
const sql = postgres(DATABASE_URL!, { prepare: false });

const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');

// Cache to reduce DB hits — tokens valid for 60s after first lookup.
const cache = new Map<string, { name: string; expires: number }>();
const CACHE_TTL_MS = 60_000;

export interface AuthResult {
  ok: boolean;
  name?: string;
  error?: string;
}

export async function validateToken(token: string): Promise<AuthResult> {
  if (!token || !token.startsWith('gbrain_') || token.length < 30) {
    return { ok: false, error: 'invalid_format' };
  }
  const hash = hashToken(token);
  const now = Date.now();

  const cached = cache.get(hash);
  if (cached && cached.expires > now) {
    return { ok: true, name: cached.name };
  }

  try {
    const rows = await sql<{ name: string; revoked_at: Date | null }[]>`
      SELECT name, revoked_at
      FROM access_tokens
      WHERE token_hash = ${hash}
      LIMIT 1
    `;
    if (rows.length === 0) {
      return { ok: false, error: 'unknown_token' };
    }
    if (rows[0].revoked_at) {
      return { ok: false, error: 'revoked' };
    }
    cache.set(hash, { name: rows[0].name, expires: now + CACHE_TTL_MS });

    // Update last_used_at (fire-and-forget, don't block)
    sql`
      UPDATE access_tokens SET last_used_at = NOW() WHERE token_hash = ${hash}
    `.catch(() => { /* non-fatal */ });

    return { ok: true, name: rows[0].name };
  } catch (e: any) {
    console.error('[auth] db error:', e.message);
    return { ok: false, error: 'db_error' };
  }
}

export async function shutdownAuth() {
  await sql.end({ timeout: 5 });
}
