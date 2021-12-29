ALTER TABLE user_profile DROP CONSTRAINT fk_user;
ALTER TABLE workspace DROP CONSTRAINT fk_user;
ALTER TABLE workspace_user DROP CONSTRAINT fk_workspace;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profile;
DROP TABLE IF EXISTS workspace;
DROP TABLE IF EXISTS workspace_user;
DROP TABLE IF EXISTS blacklisted_access_tokens;