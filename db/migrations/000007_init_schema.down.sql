ALTER TABLE IF EXISTS user_profile DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS user_session DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS login_magic_code DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS email_update_verification_code DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS dashboard DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS dashboard_member DROP CONSTRAINT foreign_key_to_dashboard_table;
ALTER TABLE IF EXISTS dashboard_member DROP CONSTRAINT foreign_key_to_user_table;
ALTER TABLE IF EXISTS dashboard_member DROP CONSTRAINT second_foreign_key_to_user_table;

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