-- OAuth 2.1 schema for gbrain-http-wrapper
-- Reuses existing access_tokens table for issued Bearer tokens.

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,                -- nullable for public clients (PKCE)
  client_name TEXT NOT NULL,
  redirect_uris TEXT[] NOT NULL,
  grant_types TEXT[] DEFAULT ARRAY['authorization_code','refresh_token'],
  token_endpoint_auth_method TEXT DEFAULT 'none',
  software_id TEXT,
  software_version TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oauth_clients_created_idx ON oauth_clients(created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  scope TEXT DEFAULT 'mcp',
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS oauth_codes_expires_idx ON oauth_codes(expires_at);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  refresh_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  access_token_name TEXT NOT NULL,         -- references access_tokens.name
  scope TEXT DEFAULT 'mcp',
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
