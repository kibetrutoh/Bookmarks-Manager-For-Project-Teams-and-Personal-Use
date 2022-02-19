CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS email_verification;
DROP TABLE IF EXISTS login_magic_code;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profle;
DROP TABLE IF EXISTS workspace;
DROP TABLE IF EXISTS workspace_users;
DROP TABLE IF EXISTS token_pair;
DROP TABLE IF EXISTS invites;

CREATE TABLE email_verification (
  email_address TEXT NOT NULL,
  verification_code TEXT NOT NULL,
  verification_code_expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(email_address)
);

CREATE TABLE login_magic_code (
  magic_code TEXT NOT NULL,
  email_address TEXT NOT NULL,
  magic_code_expiry TIMESTAMPTZ NOT NULL,
  UNIQUE(magic_code)
);

CREATE TABLE users (
  id SERIAL UNIQUE,
  full_name TEXT NOT NULL,
  email_address TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role text CHECK (role IN ('Admin', 'User')) NOT NULL DEFAULT 'User',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(id, email_address)
);

CREATE TABLE user_profile (
  user_id INT,
  CONSTRAINT fk_users FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id)
);

CREATE TABLE token_pair (
  user_id INT NOT NULL,
  access_token_id UUID NOT NULL,
  refresh_token_id UUID NOT NULL
);

CREATE TABLE workspace (
  user_id INT NOT NULL,
  id SERIAL UNIQUE,
  name TEXT NOT NULL,
  profile_image TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT CHECK (status IN ('active', 'disabled', 'suspended')) NOT NULL DEFAULT 'active',
  tier TEXT CHECK (tier IN ('gold', 'silver', 'bronze')) NOT NULL DEFAULT 'bronze',
  CONSTRAINT fk_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE,
  PRIMARY KEY (id)
);

CREATE TABLE workspace_users (
  user_id INT NOT NULL,
  workspace_id INT NOT NULL,
  access_level TEXT CHECK (access_level IN ('View Only', 'View & Edit', 'Admin')) NOT NULL,
  joined_on TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_users FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT,
  CONSTRAINT fk_workspace FOREIGN KEY(workspace_id) REFERENCES workspace(id) ON DELETE RESTRICT
);

CREATE TABLE invites (
  email_address TEXT NOT NULL,
  invitation_code TEXT NOT NULL,
  workspace_id INT,
  access_level TEXT NOT NULL
);