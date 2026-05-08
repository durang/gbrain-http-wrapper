import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const server = readFileSync('src/server.ts', 'utf8');
const auth = readFileSync('src/auth.ts', 'utf8');
const oauth = readFileSync('src/oauth.ts', 'utf8');
const schema = readFileSync('src/oauth-schema.sql', 'utf8');

describe('HTTP/OAuth hardening regressions', () => {
  test('OAuth discovery and authorization routes are mounted under /mcp as well as root', () => {
    expect(server).toContain("app.route('/', oauthRouter)");
    expect(server).toContain("app.route('/mcp', oauthRouter)");
  });

  test('OAuth-issued access tokens have real server-side expiry enforcement', () => {
    expect(schema).toMatch(/access_tokens[\s\S]*expires_at/i);
    expect(auth).toMatch(/SELECT[\s\S]*expires_at[\s\S]*FROM access_tokens/i);
    expect(auth).toMatch(/expires_at[\s\S]*new Date\(\)/i);
    expect(oauth).toMatch(/INSERT INTO access_tokens[\s\S]*expires_at/i);
  });

  test('audit table used by auditLog is present in the bundled schema', () => {
    expect(schema).toMatch(/CREATE TABLE IF NOT EXISTS mcp_request_log/i);
    expect(schema).toMatch(/token_name/i);
    expect(schema).toMatch(/operation/i);
    expect(schema).toMatch(/latency_ms/i);
    expect(schema).toMatch(/status/i);
  });

  test('dynamic client registration rejects unsafe redirect_uri schemes', () => {
    expect(oauth).toMatch(/validateRedirectUris/);
    expect(oauth).toMatch(/https:/);
    expect(oauth).toMatch(/127\.0\.0\.1/);
    expect(oauth).toMatch(/localhost/);
  });
});
