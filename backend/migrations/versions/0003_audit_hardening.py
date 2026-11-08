"""audit hardening: immutable triggers, vault_app role, indexes

Revision ID: 0003_audit_hardening
Revises: 0002_user_is_active
Create Date: 2026-11-07
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0003_audit_hardening"
down_revision = "0002_user_is_active"
branch_labels = None
depends_on = None

# ---------------------------------------------------------------------------
# Shared trigger function SQL
# ---------------------------------------------------------------------------
_CREATE_TRIGGER_FN = """\
CREATE OR REPLACE FUNCTION block_audit_events_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'audit_events table is append-only: updates, deletes, and truncations are forbidden';
END;
$$ LANGUAGE plpgsql;
"""

# ---------------------------------------------------------------------------
# upgrade helpers
# ---------------------------------------------------------------------------
_DROP_OLD_TRIGGER = """\
DROP TRIGGER IF EXISTS trg_audit_events_immutable ON audit_events;
"""

_CREATE_ROW_TRIGGER = """\
CREATE TRIGGER trg_audit_events_no_mutate
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION block_audit_events_mutation();
"""

_CREATE_STMT_TRIGGER = """\
CREATE TRIGGER trg_audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION block_audit_events_mutation();
"""

# Create vault_app role (for API runtime with restricted audit table permissions)
# and vault_migrate role (for schema migrations).
# Wrapped in a DO block so it's idempotent and non-fatal on managed DBs (e.g. Render).
_CREATE_ROLES = """\
DO $$ BEGIN
    CREATE ROLE vault_app NOLOGIN;
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Skipping CREATE ROLE vault_app due to insufficient privilege';
END $$;

DO $$ BEGIN
    CREATE ROLE vault_migrate NOLOGIN;
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Skipping CREATE ROLE vault_migrate due to insufficient privilege';
END $$;
"""

# audit_events: SELECT + INSERT only (append-only table) for vault_app, applied only if role exists.
_GRANT_PRIVILEGES = """\
DO $$ DECLARE
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        BEGIN
            GRANT SELECT, INSERT ON audit_events TO vault_app;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'Skipping GRANT on audit_events to vault_app';
        END;

        FOR r IN
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
              AND tablename <> 'audit_events'
        LOOP
            BEGIN
                EXECUTE format(
                    'GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON %I TO vault_app',
                    r.tablename
                );
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping GRANT on % to vault_app', r.tablename;
            END;
        END LOOP;

        BEGIN
            GRANT USAGE ON SEQUENCE audit_events_id_seq TO vault_app;
        EXCEPTION
            WHEN undefined_table THEN
                NULL;
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping GRANT USAGE on audit_events_id_seq to vault_app';
        END;
    END IF;
END $$;
"""

# ---------------------------------------------------------------------------
# downgrade helpers
# ---------------------------------------------------------------------------
_DROP_NEW_TRIGGERS = """\
DROP TRIGGER IF EXISTS trg_audit_events_no_mutate  ON audit_events;
DROP TRIGGER IF EXISTS trg_audit_events_no_truncate ON audit_events;
"""

_REVOKE_PRIVILEGES = """\
DO $$ DECLARE
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        BEGIN
            REVOKE ALL PRIVILEGES ON audit_events FROM vault_app;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'Skipping REVOKE on audit_events from vault_app';
        END;

        FOR r IN
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
              AND tablename <> 'audit_events'
        LOOP
            BEGIN
                EXECUTE format('REVOKE ALL PRIVILEGES ON %I FROM vault_app', r.tablename);
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping REVOKE on % from vault_app', r.tablename;
            END;
        END LOOP;

        BEGIN
            REVOKE ALL PRIVILEGES ON SEQUENCE audit_events_id_seq FROM vault_app;
        EXCEPTION
            WHEN undefined_table THEN
                NULL;
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping REVOKE on audit_events_id_seq from vault_app';
        END;
    END IF;
END $$;
"""

_DROP_ROLES = """\
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_app') THEN
        BEGIN
            DROP ROLE vault_app;
        EXCEPTION
            WHEN undefined_object THEN NULL;
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping DROP ROLE vault_app';
        END;
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_migrate') THEN
        BEGIN
            DROP ROLE vault_migrate;
        EXCEPTION
            WHEN undefined_object THEN NULL;
            WHEN insufficient_privilege THEN
                RAISE NOTICE 'Skipping DROP ROLE vault_migrate';
        END;
    END IF;
END $$;
"""



def upgrade() -> None:
    # 1. Recreate trigger function and replace single trigger with two triggers.
    op.execute(_CREATE_TRIGGER_FN)
    op.execute(_DROP_OLD_TRIGGER)
    op.execute(_CREATE_ROW_TRIGGER)
    op.execute(_CREATE_STMT_TRIGGER)

    # 2. Safely create roles and apply grants if permitted.
    op.execute(_CREATE_ROLES)
    op.execute(_GRANT_PRIVILEGES)

    # 3. Add indexes on audit_events (independent of roles).
    op.create_index("idx_audit_actor",    "audit_events", ["actor_id"])
    op.create_index("idx_audit_action",   "audit_events", ["action"])
    op.create_index("idx_audit_outcome",  "audit_events", ["outcome"])
    op.create_index("idx_audit_actor_ts", "audit_events", ["actor_id", "ts"])


def downgrade() -> None:
    # 1. Drop new indexes.
    op.drop_index("idx_audit_actor_ts", table_name="audit_events")
    op.drop_index("idx_audit_outcome",  table_name="audit_events")
    op.drop_index("idx_audit_action",   table_name="audit_events")
    op.drop_index("idx_audit_actor",    table_name="audit_events")

    # 2. Revoke privileges and drop roles if permitted.
    op.execute(_REVOKE_PRIVILEGES)
    op.execute(_DROP_ROLES)

    # 3. Drop the two new triggers (function is left in place intentionally;
    #    dropping it would break any other triggers that may reference it).
    op.execute(_DROP_NEW_TRIGGERS)

