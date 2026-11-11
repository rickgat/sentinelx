-- Role-based access control. Roles and permissions are tenant-scoped
-- (each tenant may customise their own role taxonomy on top of the
-- shipped defaults). Permissions are short ASCII strings of the form
-- `<resource>:<action>` (e.g. `engagement:create`, `finding:resolve`).

CREATE TABLE roles (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    description TEXT NOT NULL DEFAULT '',
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX roles_tenant_idx ON roles (tenant_id);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY,
    -- Permissions are global (not tenant-scoped); they describe what
    -- *capabilities* exist in the platform.
    name        TEXT NOT NULL UNIQUE
                CHECK (name ~ '^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$'),
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE role_permissions (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX role_permissions_perm_idx ON role_permissions (permission_id);

CREATE TABLE user_roles (
    tenant_id   UUID NOT NULL,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, role_id)
);

CREATE INDEX user_roles_user_idx ON user_roles (tenant_id, user_id);
CREATE INDEX user_roles_role_idx ON user_roles (tenant_id, role_id);
