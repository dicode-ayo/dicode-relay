-- 001_init.sql — initial schema for dicode-relay persistence layer.
-- See issue #12 in dicode-ayo/dicode-relay.

CREATE TABLE users (
  id                            INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id                     INTEGER UNIQUE NOT NULL,
  github_login                  TEXT NOT NULL,
  email                         TEXT,
  github_access_token_encrypted BLOB,
  created_at                    INTEGER NOT NULL
);

CREATE TABLE daemons (
  uuid        TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label       TEXT,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);
CREATE INDEX daemons_user_id ON daemons(user_id);

CREATE TABLE plans (
  user_id            INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  tier               TEXT NOT NULL CHECK (tier IN ('free','pro','team')),
  hook_quota_monthly INTEGER NOT NULL,
  concurrent_daemons INTEGER NOT NULL,
  oauth_providers    TEXT NOT NULL,
  stripe_sub_id      TEXT,
  renews_at          INTEGER
);

CREATE TABLE hook_usage (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period  TEXT NOT NULL,
  count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, period)
);
