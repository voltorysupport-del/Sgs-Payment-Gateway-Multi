-- Existing credentials retain their current read/write simulator permissions.
ALTER TABLE operator_api_keys
    ADD COLUMN permission TEXT NOT NULL DEFAULT 'read_write'
    CHECK (permission IN ('read_only', 'read_write'));
