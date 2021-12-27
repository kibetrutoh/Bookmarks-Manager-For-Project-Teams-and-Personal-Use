ALTER TABLE user_profile DROP CONSTRAINT fk_users;
ALTER TABLE tenant DROP CONSTRAINT fk_users;
ALTER TABLE tenant_user DROP CONSTRAINT fk_tenant;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profile;
DROP TABLE IF EXISTS tenant;
DROP TABLE IF EXISTS tenant_user;
DROP TABLE IF EXISTS blacklisted_access_tokens;