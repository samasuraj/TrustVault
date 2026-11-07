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
# Wrapped in a DO block so it's idempotent.
_CREATE_ROLE = """\
DO $$ BEGIN
    CREATE ROLE vault_app NOLOGIN;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

DO $$ BEGIN
    CREATE ROLE vault_migrate NOLOGIN SUPERUSER;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;
"""

# audit_events: SELECT + INSERT only (append-only table).
_GRANT_AUDIT = """\
GRANT SELECT, INSERT ON audit_events TO vault_app;
"""

# All other tables: full DML + REFERENCES.
_GRANT_OTHER_TABLES = """\
DO $$ DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename <> 'audit_events'
    LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON %I TO vault_app',
            r.tablename
        );
    END LOOP;
END $$;
"""

# Sequence on audit_events (auto-increment id).
_GRANT_SEQUENCE = """\
DO $$ BEGIN
    GRANT USAGE ON SEQUENCE audit_events_id_seq TO vault_app;
EXCEPTION WHEN undefined_table THEN
    NULL;
END $$;
"""

# ---------------------------------------------------------------------------
# downgrade helpers
# ---------------------------------------------------------------------------
_DROP_NEW_TRIGGERS = """\
DROP TRIGGER IF EXISTS trg_audit_events_no_mutate  ON audit_events;
DROP TRIGGER IF EXISTS trg_audit_events_no_truncate ON audit_events;
"""

_REVOKE_AUDIT = """\
REVOKE ALL PRIVILEGES ON audit_events FROM vault_app;
"""

_REVOKE_OTHER_TABLES = """\
DO $$ DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename <> 'audit_events'
    LOOP
        EXECUTE format('REVOKE ALL PRIVILEGES ON %I FROM vault_app', r.tablename);
    END LOOP;
END $$;
"""

_REVOKE_SEQUENCE = """\
DO $$ BEGIN
    REVOKE ALL PRIVILEGES ON SEQUENCE audit_events_id_seq FROM vault_app;
EXCEPTION WHEN undefined_table THEN
    NULL;
END $$;
"""

_DROP_ROLE = """\
DO $$ BEGIN
    DROP ROLE vault_app;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;

DO $$ BEGIN
    DROP ROLE vault_migrate;
EXCEPTION WHEN undefined_object THEN
    NULL;
END $$;
"""


def upgrade() -> None:
    # 1. Recreate trigger function and replace single trigger with two triggers.
    op.execute(_CREATE_TRIGGER_FN)
    op.execute(_DROP_OLD_TRIGGER)
    op.execute(_CREATE_ROW_TRIGGER)
    op.execute(_CREATE_STMT_TRIGGER)

    # 2. Create vault_app role and apply grants.
    op.execute(_CREATE_ROLE)
    op.execute(_GRANT_AUDIT)
    op.execute(_GRANT_OTHER_TABLES)
    op.execute(_GRANT_SEQUENCE)

    # 3. Add indexes on audit_events.
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

    # 2. Revoke privileges and drop role.
    op.execute(_REVOKE_SEQUENCE)
    op.execute(_REVOKE_OTHER_TABLES)
    op.execute(_REVOKE_AUDIT)
    op.execute(_DROP_ROLE)

    # 3. Drop the two new triggers (function is left in place intentionally;
    #    dropping it would break any other triggers that may reference it).
    op.execute(_DROP_NEW_TRIGGERS)
