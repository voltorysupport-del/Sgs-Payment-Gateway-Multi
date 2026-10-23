CREATE TABLE operators (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE payments (
    id UUID PRIMARY KEY,
    operator_id UUID NOT NULL
        REFERENCES operators(id),
    provider TEXT NOT NULL DEFAULT 'simulator'
        CHECK (provider IN ('simulator')),
    provider_reference TEXT,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency CHAR(3) NOT NULL
        CHECK (currency ~ '^[A-Z]{3}$'),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN (
            'pending',
            'succeeded',
            'failed',
            'cancelled'
        )),
    idempotency_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (operator_id, idempotency_key)
);

CREATE INDEX payments_operator_created_idx
    ON payments (operator_id, created_at DESC);

CREATE INDEX payments_provider_reference_idx
    ON payments (provider, provider_reference)
    WHERE provider_reference IS NOT NULL;