CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profle;
DROP TABLE IF EXISTS tenant;
DROP TABLE IF EXISTS tenant_user;
DROP TABLE IF EXISTS blacklisted_access_tokens;

CREATE TABLE users (
  user_id UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
  full_name TEXT NOT NULL,
  email_address TEXT NOT NULL UNIQUE,
  hashed_password TEXT NOT NULL,
  hashed_password_updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  role text CHECK (role IN ('admin', 'user')) DEFAULT 'user',
  active BOOLEAN NOT NULL DEFAULT FALSE,
  verification_code TEXT NOT NULL,
  verificaton_code_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  refresh_token_id UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
  PRIMARY KEY(user_id, email_address)
);

CREATE TABLE blacklisted_access_tokens (
  token_id UUID NOT NULL
);

CREATE TABLE user_profile (
  user_id UUID NOT NULL,
  CONSTRAINT fk_users FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
  PRIMARY KEY(user_id)
);

CREATE TABLE tenant (
  user_id UUID NOT NULL,
  tenant_id UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
  tenant_name TEXT NOT NULL UNIQUE,
  project_name TEXT NOT NULL,
  image_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT CHECK (status IN ('active', 'disabled', 'suspended')) NOT NULL DEFAULT 'active',
  tier TEXT CHECK (tier IN ('gold', 'silver', 'bronze')) NOT NULL DEFAULT 'bronze',
  CONSTRAINT fk_users FOREIGN KEY(user_id) REFERENCES users (user_id) ON DELETE CASCADE,
  PRIMARY KEY (tenant_id, tenant_name)
);

CREATE TABLE tenant_user (
  tenant_user_id UUID NOT NULL DEFAULT uuid_generate_v4() UNIQUE,
  parent_tenant_id UUID NOT NULL,
  full_name TEXT NOT NULL DEFAULT 'Default Full Name',
  email_address TEXT NOT NULL,
  hashed_password TEXT NOT NULL DEFAULT 'B33608080rm/2018/30333',
  access_level TEXT CHECK (access_level IN ('View Only', 'View & Edit', 'Admin')) NOT NULL DEFAULT 'View & Edit',
  invitation_token UUID NOT NULL,
  accepted_invite BOOLEAN NOT NULL DEFAULT 'false',
  accepted_invite_on TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_tenant FOREIGN KEY(parent_tenant_id) REFERENCES tenant(tenant_id) ON DELETE RESTRICT,
  PRIMARY KEY(tenant_user_id, email_address)
);
