
-- Store only hashes of operator API keys, never the raw secrets.
CREATE TABLE operator_api_keys (
    id UUID PRIMARY KEY,
    operator_id UUID NOT NULL
        REFERENCES operators(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    key_hash CHAR(64) NOT NULL UNIQUE
        CHECK (key_hash ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX operator_api_keys_active_operator_idx
    ON operator_api_keys (operator_id)
    WHERE revoked_at IS NULL;
