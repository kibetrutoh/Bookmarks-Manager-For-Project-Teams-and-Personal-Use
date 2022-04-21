CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS administrator;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profile;
DROP TABLE IF EXISTS user_session;
DROP TABLE IF EXISTS login_magic_code;
DROP TABLE IF EXISTS signup_email_verification_code;
DROP TABLE IF EXISTS email_update_verification_code;
DROP TABLE IF EXISTS invite;
DROP TABLE IF EXISTS dashboard;
DROP TABLE IF EXISTS dashboard_member;

CREATE TABLE administrator (
  id UUID NOT NULL DEFAULT uuid_generate_v4 () UNIQUE,
  name TEXT NOT NULL,
  email_address TEXT NOT NULL,
  password TEXT NOT NULL,
  PRIMARY KEY (id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id SERIAL UNIQUE,
    full_name TEXT NOT NULL,
    email_address TEXT NOT NULL UNIQUE,
    client_os TEXT NOT NULL,
    client_agent TEXT NOT NULL,
    client_browser TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(id, email_address)
);

CREATE TABLE user_profile (
  user_id INT,
  profile_image TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id),
  CONSTRAINT foreign_key_to_user_table
    FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE
);

CREATE TABLE user_session (
  id UUID,
  user_id INT NOT NULL,
  refresh_token TEXT NOT NULL,
  client_agent TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  client_os TEXT NOT NULL,
  active BOOLEAN DEFAULT 'true' NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT foreign_key_to_user_table
    FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE
);

CREATE TABLE login_magic_code (
  id UUID DEFAULT uuid_generate_v4 () UNIQUE,
  user_id INT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  email_address TEXT NOT NULL,
  code_expiry TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT foreign_key_to_user_table
    FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE
);

CREATE TABLE email_update_verification_code (
  id UUID DEFAULT uuid_generate_v4 () UNIQUE,
  user_id INT NOT NULL,
  code TEXT NOT NULL,
  email_address TEXT NOT NULL UNIQUE,
  expiry TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(id, code),
  CONSTRAINT foreign_key_to_user_table
    FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE
);

CREATE TABLE signup_email_verification_code (
  id UUID DEFAULT uuid_generate_v4 () UNIQUE,
  email_address TEXT NOT NULL UNIQUE,
  verification_code TEXT NOT NULL,
  expiry TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE invite (
  id UUID DEFAULT uuid_generate_v4 () UNIQUE,
  invite_from INT NOT NULL,
  student_email_address TEXT NOT NULL,
  invitation_code TEXT NOT NULL,
  dashboard_id INT,
  access_level TEXT NOT NULL,
  invite_expiry TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (id)
);

CREATE TABLE dashboard (
  id TEXT UNIQUE,
  dashboard_admin INT NOT NULL,
  dashboard_name TEXT NOT NULL,
  logo TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT CHECK (status IN ('active', 'disabled', 'suspended')) NOT NULL DEFAULT 'active',
  plan TEXT NOT NULL CHECK (plan IN ('Free', 'Pro', 'Blaze')) DEFAULT 'Free',
  PRIMARY KEY (id),
  CONSTRAINT foreign_key_to_user_table
   FOREIGN KEY (dashboard_admin)
    REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE TABLE dashboard_member (
  id SERIAL UNIQUE,
  user_id INT NOT NULL,
  dashboard_id TEXT NOT NULL,
  invited_by INT NOT NULL,
  invited_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  accepted_invitation BOOLEAN DEFAULT 'false',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  access_level TEXT CHECK (access_level IN ('View Only', 'View & Edit', 'Admin')) NOT NULL DEFAULT 'View Only',
  CONSTRAINT foreign_key_to_dashboard_table
    FOREIGN KEY (dashboard_id)
        REFERENCES dashboard (id)
            ON DELETE CASCADE,
  CONSTRAINT foreign_key_to_user_table
    FOREIGN KEY (user_id)
        REFERENCES users (id)
            ON DELETE CASCADE,
  CONSTRAINT second_foreign_key_to_user_table
    FOREIGN KEY (invited_by)
        REFERENCES users (id)
            ON DELETE CASCADE
);