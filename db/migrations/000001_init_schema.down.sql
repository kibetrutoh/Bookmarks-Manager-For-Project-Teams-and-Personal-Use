ALTER TABLE IF EXISTS user_profile
    DROP CONSTRAINT foreign_key_to_users_table;

ALTER TABLE IF EXISTS user_sessions
    DROP CONSTRAINT foreign_key_to_users_table;

ALTER TABLE IF EXISTS dashboard
    DROP CONSTRAINT foreign_key_to_users_table;

ALTER TABLE IF EXISTS dashboard_members
    DROP CONSTRAINT foreign_key_to_users_table;

ALTER TABLE IF EXISTS dashboard_members
    DROP CONSTRAINT foreign_key_to_dashboard_table;

DROP TABLE IF EXISTS email_verification;
DROP TABLE IF EXISTS login_magic_code;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_profile;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS workspace;
DROP TABLE IF EXISTS workspace_users;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS email_verification;