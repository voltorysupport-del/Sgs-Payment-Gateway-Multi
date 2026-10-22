-- Runs automatically the first time the local Postgres container starts.
-- Creates a separate database for automated tests, so tests never touch
-- your development data. Tables are added by migrations from Step 2 onwards.
CREATE DATABASE vaultx_pay_test;
