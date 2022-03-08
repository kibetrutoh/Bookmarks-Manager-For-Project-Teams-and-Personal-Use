CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS email_verification;
DROP TABLE IF EXISTS login_magic_code;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profle;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS dashboard;
DROP TABLE IF EXISTS dashboard_members;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS change_email;

CREATE TABLE users (
  id SERIAL UNIQUE,
  full_name TEXT NOT NULL,
  email_address TEXT NOT NULL UNIQUE,
  client_os TEXT NOT NULL,
  client_agent TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  client_browser TEXT NOT NULL,
  password TEXT NOT NULL,
  role text CHECK (role IN ('Admin', 'User')) NOT NULL DEFAULT 'User',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(id, email_address)
);

CREATE TABLE user_profile (
  user_id INT,
  PRIMARY KEY(user_id)
);

CREATE TABLE change_email (
  user_id INT NOT NULL,
  code TEXT NOT NULL,
  email_address TEXT NOT NULL UNIQUE,
  expiry TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(code)
);

CREATE TABLE email_verification (
  email_address TEXT NOT NULL,
  verification_code TEXT NOT NULL,
  verification_code_expires_at TIMESTAMPTZ NOT NULL,
  UNIQUE(email_address)
);

CREATE TABLE login_magic_code (
  user_id INT NOT NULL,
  code TEXT NOT NULL,
  email_address TEXT NOT NULL,
  code_expiry TIMESTAMPTZ NOT NULL,
  UNIQUE(code)
);

CREATE TABLE user_sessions (
  id UUID,
  user_id INT NOT NULL,
  refresh_token TEXT NOT NULL,
  client_agent TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  client_os TEXT NOT NULL,
  active BOOLEAN DEFAULT 'true' NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(id)
);

CREATE TABLE dashboard (
  user_id INT NOT NULL,
  id SERIAL UNIQUE,
  name TEXT NOT NULL,
  profile_image TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT CHECK (status IN ('active', 'disabled', 'suspended')) NOT NULL DEFAULT 'active',
  tier TEXT CHECK (tier IN ('gold', 'silver', 'bronze')) NOT NULL DEFAULT 'bronze',
  PRIMARY KEY (id)
);

CREATE TABLE dashboard_members (
  user_id INT NOT NULL,
  dashboard_id INT NOT NULL,
  access_level TEXT CHECK (access_level IN ('View Only', 'View & Edit', 'Admin')) NOT NULL,
  joined_on TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE invites (
  email_address TEXT NOT NULL,
  invitation_code TEXT NOT NULL,
  workspace_id INT,
  access_level TEXT NOT NULL
);

ALTER TABLE change_email
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;

ALTER TABLE login_magic_code
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;

ALTER TABLE user_profile
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;

ALTER TABLE user_sessions
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;

ALTER TABLE dashboard
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;

ALTER TABLE dashboard_members
  ADD CONSTRAINT foreign_key_to_users_table
    FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE RESTRICT;

ALTER TABLE dashboard_members
  ADD CONSTRAINT foreign_key_to_dashboard_table
    FOREIGN KEY(dashboard_id)
    REFERENCES dashboard(id)
    ON DELETE RESTRICT;