-- Dashboard identities are distinct from operator API credentials.
CREATE TABLE dashboard_users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_.-]{2,79}$'),
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    auth_version INTEGER NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE dashboard_memberships (
    user_id UUID PRIMARY KEY REFERENCES dashboard_users(id) ON DELETE CASCADE,
    operator_id UUID NOT NULL REFERENCES operators(id),
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role = 'viewer'),
    -- Recreating a membership must not revive sessions for the previous membership.
    id UUID NOT NULL UNIQUE
);
CREATE TABLE dashboard_sessions (
    token_hash CHAR(64) PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    csrf_hash CHAR(64) NOT NULL,
    user_id UUID REFERENCES dashboard_users(id) ON DELETE CASCADE,
    membership_id UUID REFERENCES dashboard_memberships(id) ON DELETE CASCADE,
    auth_version INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((user_id IS NULL AND membership_id IS NULL AND auth_version IS NULL)
        OR (user_id IS NOT NULL AND membership_id IS NOT NULL AND auth_version IS NOT NULL))
);
CREATE INDEX dashboard_sessions_user_idx ON dashboard_sessions(user_id);
CREATE INDEX dashboard_sessions_created_idx ON dashboard_sessions(created_at);
CREATE TABLE dashboard_login_limits (
    bucket_hash CHAR(64) PRIMARY KEY,
    attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX dashboard_login_limits_expiry_idx ON dashboard_login_limits(expires_at);

-- Enforce invalidation even when an administrator updates records directly.
CREATE FUNCTION invalidate_dashboard_user_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash OR NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.auth_version := OLD.auth_version + 1;
        DELETE FROM dashboard_sessions WHERE user_id = OLD.id;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dashboard_user_invalidation BEFORE UPDATE ON dashboard_users
    FOR EACH ROW EXECUTE FUNCTION invalidate_dashboard_user_sessions();
CREATE FUNCTION invalidate_dashboard_membership_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM dashboard_sessions WHERE membership_id = OLD.id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dashboard_membership_invalidation BEFORE UPDATE ON dashboard_memberships
    FOR EACH ROW EXECUTE FUNCTION invalidate_dashboard_membership_sessions();
CREATE FUNCTION invalidate_suspended_operator_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'suspended' AND OLD.status IS DISTINCT FROM NEW.status THEN
        DELETE FROM dashboard_sessions WHERE membership_id IN
            (SELECT id FROM dashboard_memberships WHERE operator_id = OLD.id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER dashboard_operator_invalidation BEFORE UPDATE ON operators
    FOR EACH ROW EXECUTE FUNCTION invalidate_suspended_operator_sessions();
