-- Initialize PostgreSQL databases for SSO application
-- This script is run automatically on Docker startup
-- Note: This runs as postgres superuser with postgres database selected

-- Create test database if it doesn't exist
CREATE DATABASE sso_test;

-- Grant privileges to the user
ALTER ROLE "user" WITH CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE sso_test TO "user";
