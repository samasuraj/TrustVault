"""
Tests for audit trail hardening:
- HMAC-SHA256 chain (log_event / record_audit)
- verify_chain() detects tampering
- DB-level trigger blocks UPDATE / DELETE on audit_events
- Trigger blocks TRUNCATE on audit_events
- Admin endpoints: /admin/audit, /admin/audit/verify, /admin/activity
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
import psycopg2
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_db
from app.deps import get_current_user, require_admin
from app.models import AuditEvent, User
from app.authz import log_event, verify_chain, _hmac_hash
from app.config import cfg

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_admin():
    return User(
        id=uuid.uuid4(), email="admin@tv.local", name="Admin",
        pw_hash="h", role="admin", is_active=True, token_version=1,
    )


def _make_audit_event(id_, ts, action, outcome, actor_id, prev_hash, detail=None):
    payload = {
        "ts": ts.isoformat(),
        "actor_id": str(actor_id) if actor_id else None,
        "action": action,
        "doc_id": None,
        "target_user_id": None,
        "outcome": outcome,
        "ip": None,
        "detail": detail or {},
    }
    h = _hmac_hash(prev_hash, payload)
    evt = AuditEvent(
        id=id_,
        ts=ts,
        actor_id=actor_id,
        action=action,
        doc_id=None,
        target_user_id=None,
        outcome=outcome,
        ip=None,
        detail=detail or {},
        prev_hash=prev_hash,
        hash=h,
    )
    return evt


# ---------------------------------------------------------------------------
# Unit: HMAC chain
# ---------------------------------------------------------------------------

class TestHmacChain:
    def test_hmac_uses_secret_key(self):
        payload = {"ts": "2026-01-01T00:00:00+00:00", "action": "login", "outcome": "allowed",
                   "actor_id": None, "doc_id": None, "target_user_id": None, "ip": None, "detail": {}}
        h1 = _hmac_hash(None, payload)
        h2 = _hmac_hash(None, payload)
        assert h1 == h2  # deterministic

        # Different prev_hash → different hash
        h3 = _hmac_hash("prev123", payload)
        assert h1 != h3

    def test_hmac_different_from_sha256(self):
        payload = {"ts": "t", "action": "a", "outcome": "allowed",
                   "actor_id": None, "doc_id": None, "target_user_id": None, "ip": None, "detail": {}}
        hmac_hash = _hmac_hash(None, payload)
        # Ensure it's actually HMAC (not plain SHA-256)
        raw = f":{json.dumps(payload, sort_keys=True)}"
        plain_sha256 = hashlib.sha256(raw.encode()).hexdigest()
        assert hmac_hash != plain_sha256

    def test_log_event_writes_valid_chain(self):
        db = MagicMock()
        db.query.return_value.order_by.return_value.with_for_update.return_value.first.return_value = None
        db.execute.return_value = None

        actor_id = uuid.uuid4()
        # Capture the AuditEvent added to the db
        added = []
        db.add.side_effect = lambda x: added.append(x)
        db.commit.return_value = None
        db.refresh.side_effect = lambda x: None

        evt = log_event(db, action="login", outcome="allowed", actor_id=actor_id, ip="1.2.3.4")

        assert len(added) == 1
        assert added[0].prev_hash is None
        assert len(added[0].hash) == 64  # sha256 hex

    def test_log_event_chains_from_previous(self):
        prev_id = uuid.uuid4()
        prev_hash = "a" * 64
        prev_evt = MagicMock()
        prev_evt.hash = prev_hash

        db = MagicMock()
        db.query.return_value.order_by.return_value.with_for_update.return_value.first.return_value = prev_evt
        db.execute.return_value = None

        added = []
        db.add.side_effect = lambda x: added.append(x)
        db.commit.return_value = None
        db.refresh.side_effect = lambda x: None

        log_event(db, action="download", outcome="allowed", actor_id=prev_id)

        assert added[0].prev_hash == prev_hash


# ---------------------------------------------------------------------------
# Unit: verify_chain
# ---------------------------------------------------------------------------

class TestVerifyChain:
    def _make_db_with_events(self, events):
        db = MagicMock()
        q = MagicMock()
        q.order_by.return_value.all.return_value = events
        db.query.return_value = q
        return db

    def test_empty_chain_ok(self):
        db = self._make_db_with_events([])
        result = verify_chain(db)
        assert result["ok"] is True
        assert result["total_events"] == 0

    def test_valid_chain_ok(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        e1 = _make_audit_event(1, now, "login", "allowed", actor, None)
        e2 = _make_audit_event(2, now, "download", "allowed", actor, e1.hash)

        db = self._make_db_with_events([e1, e2])
        result = verify_chain(db)
        assert result["ok"] is True
        assert result["total_events"] == 2

    def test_tampered_hash_detected(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        e1 = _make_audit_event(1, now, "login", "allowed", actor, None)
        # Tamper e1.hash
        e1.hash = "deadbeef" * 8

        db = self._make_db_with_events([e1])
        result = verify_chain(db)
        assert result["ok"] is False
        assert result["broken_at_id"] == 1
        assert result["reason"] == "hash_mismatch"

    def test_tampered_prev_hash_detected(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        e1 = _make_audit_event(1, now, "login", "allowed", actor, None)
        # e2 references wrong prev_hash
        e2 = _make_audit_event(2, now, "download", "allowed", actor, "wrongprev" + "0" * 55)

        db = self._make_db_with_events([e1, e2])
        result = verify_chain(db)
        assert result["ok"] is False
        assert result["broken_at_id"] == 2
        assert result["reason"] == "prev_hash_mismatch"

    def test_field_mutation_detected(self):
        """Changing a field value in an event breaks its hash."""
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        e1 = _make_audit_event(1, now, "login", "allowed", actor, None)
        # Mutate the action field AFTER computing hash
        e1.action = "download"

        db = self._make_db_with_events([e1])
        result = verify_chain(db)
        assert result["ok"] is False
        assert result["broken_at_id"] == 1


# ---------------------------------------------------------------------------
# Integration: DB trigger blocks UPDATE / DELETE / TRUNCATE
# ---------------------------------------------------------------------------

class TestAuditTriggerInDB:
    """These tests connect directly to the real Postgres DB in Docker.
    They are skipped when DATABASE_URL points to a mock / no DB is available."""

    @pytest.fixture
    def raw_conn(self):
        dsn = cfg.database_url.replace("postgresql+psycopg2://", "postgresql://")
        try:
            conn = psycopg2.connect(dsn)
            conn.autocommit = False
            yield conn
            conn.rollback()
            conn.close()
        except Exception:
            pytest.skip("No live database available")

    def _insert_event(self, conn):
        """Insert one audit event directly via psycopg2, preserving HMAC chain."""
        from app.audit import compute_hash, format_ts
        with conn.cursor() as cur:
            cur.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1")
            last_row = cur.fetchone()
            prev_h = last_row[0] if last_row else None
            now = datetime.now(timezone.utc)
            payload = {
                "ts": format_ts(now),
                "actor_id": None,
                "action": "test_action",
                "doc_id": None,
                "target_user_id": None,
                "outcome": "allowed",
                "ip": "127.0.0.1",
                "detail": {},
            }
            h = compute_hash(cfg.audit_hmac_key, prev_h, payload)
            cur.execute(
                """
                INSERT INTO audit_events (ts, action, outcome, ip, detail, prev_hash, hash)
                VALUES (%s, 'test_action', 'allowed', '127.0.0.1', '{}', %s, %s)
                RETURNING id
                """,
                (now, prev_h, h),
            )
            row = cur.fetchone()
            conn.commit()
            return row[0]


    def test_update_audit_event_raises(self, raw_conn):
        event_id = self._insert_event(raw_conn)
        with pytest.raises(psycopg2.errors.RaiseException) as exc:
            with raw_conn.cursor() as cur:
                cur.execute(
                    "UPDATE audit_events SET action = 'tampered' WHERE id = %s",
                    (event_id,),
                )
        assert "append-only" in str(exc.value).lower()

    def test_delete_audit_event_raises(self, raw_conn):
        event_id = self._insert_event(raw_conn)
        raw_conn.rollback()  # clean state
        event_id = self._insert_event(raw_conn)
        with pytest.raises(psycopg2.errors.RaiseException) as exc:
            with raw_conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM audit_events WHERE id = %s",
                    (event_id,),
                )
        assert "append-only" in str(exc.value).lower()

    def test_truncate_audit_event_raises(self, raw_conn):
        with pytest.raises(psycopg2.errors.RaiseException) as exc:
            with raw_conn.cursor() as cur:
                cur.execute("TRUNCATE audit_events")
        assert "append-only" in str(exc.value).lower()

    def test_hash_chain_verify_detects_tampered_row(self, raw_conn):
        """Test that altering a row's hash in PostgreSQL is detected by verify_chain."""
        from app.db import SessionLocal
        from app.audit import verify_chain

        event_id = self._insert_event(raw_conn)
        db = SessionLocal()
        try:
            # Confirm chain is intact
            initial = verify_chain(db)
            assert initial["ok"] is True

            # Tamper the event by temporarily disabling trigger, modifying hash, re-enabling trigger
            with raw_conn.cursor() as cur:
                cur.execute("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_mutate")
                cur.execute(
                    "UPDATE audit_events SET hash = 'deadbeef' || substr(hash, 9) WHERE id = %s",
                    (event_id,),
                )
                cur.execute("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_mutate")
                raw_conn.commit()

            # verify_chain must detect the tampered row
            res = verify_chain(db)
            assert res["ok"] is False
            assert res["broken_at_id"] == event_id
            assert res["reason"] == "hash_mismatch"
        finally:
            # Clean up the test event so the audit chain remains intact
            with raw_conn.cursor() as cur:
                cur.execute("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_mutate")
                cur.execute("DELETE FROM audit_events WHERE id = %s", (event_id,))
                cur.execute("ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_mutate")
                raw_conn.commit()
            db.close()



# ---------------------------------------------------------------------------
# Admin endpoint tests (mocked DB)
# ---------------------------------------------------------------------------

class TestAdminAuditEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.admin = _make_admin()
        self.mock_db = MagicMock()
        app.dependency_overrides[get_db] = lambda: self.mock_db
        app.dependency_overrides[get_current_user] = lambda: self.admin
        app.dependency_overrides[require_admin] = lambda: self.admin
        self.c = TestClient(app)
        yield
        app.dependency_overrides.clear()

    def _mock_audit_events(self, events):
        """Setup mock_db to return events for audit queries."""
        q = MagicMock()
        q.filter.return_value = q
        q.order_by.return_value = q
        q.offset.return_value = q
        q.limit.return_value = q
        q.all.return_value = events
        q.count.return_value = len(events)
        q.group_by.return_value = q
        q.having.return_value = q
        q.first.return_value = events[-1] if events else None
        self.mock_db.query.return_value = q
        # for log_event inside the endpoint
        self.mock_db.execute.return_value = None
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.side_effect = lambda x: None
        return q

    def test_audit_verify_ok_on_empty(self):
        now = datetime.now(timezone.utc)
        q = MagicMock()
        q.order_by.return_value.all.return_value = []
        q.order_by.return_value.with_for_update.return_value.first.return_value = None
        q.order_by.return_value.first.return_value = None
        self.mock_db.query.return_value = q
        self.mock_db.execute.return_value = None
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.side_effect = lambda x: None

        res = self.c.get("/api/admin/audit/verify")
        assert res.status_code == 200
        assert res.json()["ok"] is True

    def test_audit_list_paginated(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        events = [
            AuditEvent(
                id=i, ts=now, actor_id=actor, action="login", doc_id=None,
                target_user_id=None, outcome="allowed", ip="1.2.3.4",
                detail={}, prev_hash=None, hash="a" * 64,
            )
            for i in range(1, 6)
        ]
        self._mock_audit_events(events)

        res = self.c.get("/api/admin/audit?page=1&per_page=5")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)

    def test_audit_list_requires_admin(self):
        # Override to non-admin user
        viewer = User(id=uuid.uuid4(), email="v@tv.local", name="V", pw_hash="h",
                      role="viewer", is_active=True, token_version=1)
        app.dependency_overrides[require_admin] = lambda: (_ for _ in ()).throw(
            __import__("fastapi").HTTPException(status_code=403, detail="Admin only")
        )
        res = self.c.get("/api/admin/audit")
        assert res.status_code in (401, 403, 422)

    def test_audit_verify_detects_broken_chain(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        # Build two events where e2.prev_hash is wrong
        e1 = _make_audit_event(1, now, "login", "allowed", actor, None)
        e2 = _make_audit_event(2, now, "download", "allowed", actor, "wrongprev" + "0" * 55)

        q = MagicMock()
        q.order_by.return_value.all.return_value = [e1, e2]
        q.order_by.return_value.with_for_update.return_value.first.return_value = None
        q.order_by.return_value.first.return_value = None
        self.mock_db.query.return_value = q
        self.mock_db.execute.return_value = None
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.side_effect = lambda x: None

        res = self.c.get("/api/admin/audit/verify")
        assert res.status_code == 200
        result = res.json()
        assert result["ok"] is False
        assert result["broken_at_id"] == 2

    def test_activity_summary_returns_expected_structure(self):
        q = MagicMock()
        q.filter.return_value = q
        q.count.return_value = 42
        q.group_by.return_value = q
        q.order_by.return_value = q
        q.having.return_value = q
        q.limit.return_value = q
        q.all.return_value = []
        q.first.return_value = None
        q.with_for_update.return_value = q
        self.mock_db.query.return_value = q
        self.mock_db.execute.return_value = None
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.side_effect = lambda x: None

        res = self.c.get("/api/admin/activity")
        assert res.status_code == 200
        data = res.json()
        assert "total_events" in data
        assert "by_action" in data
        assert "by_outcome" in data
        assert "alerts" in data
        assert "alert_count" in data

    def test_audit_csv_export(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        events = [
            AuditEvent(
                id=1, ts=now, actor_id=actor, action="doc_download", doc_id=uuid.uuid4(),
                target_user_id=None, outcome="allowed", ip="10.0.0.1",
                detail={"size": 100}, prev_hash=None, hash="h1" * 32,
            )
        ]
        self._mock_audit_events(events)

        res = self.c.get("/api/admin/audit?export=csv")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        assert "attachment; filename=audit_events.csv" in res.headers["content-disposition"]
        content = res.text
        assert "id,ts,actor_id,action,doc_id" in content
        assert "doc_download" in content

    def test_admin_routes_without_api_prefix(self):
        self._mock_audit_events([])
        # Verify /admin/audit/verify works
        res = self.c.get("/admin/audit/verify")
        assert res.status_code == 200

        # Verify /admin/audit works
        res = self.c.get("/admin/audit")
        assert res.status_code == 200

        # Verify /admin/activity works
        res = self.c.get("/admin/activity")
        assert res.status_code == 200

    def test_audit_filtering_parameters(self):
        q = self._mock_audit_events([])
        target_u = uuid.uuid4()
        target_d = uuid.uuid4()

        res = self.c.get(
            f"/api/admin/audit?actor_id={target_u}&doc_id={target_d}&action=download&outcome=denied&page=2&per_page=10"
        )
        assert res.status_code == 200
        # Check that query.filter was called for each parameter
        assert q.filter.call_count >= 4
        q.offset.assert_called_with(10)
        q.limit.assert_called_with(10)

    def test_user_activity_returns_enriched_events(self):
        now = datetime.now(timezone.utc)
        actor = uuid.uuid4()
        user = User(id=actor, email="user@tv.local", name="Target User", role="owner")
        event = AuditEvent(
            id=101, ts=now, actor_id=actor, action="auth_login", doc_id=None,
            target_user_id=None, outcome="allowed", ip="127.0.0.1",
            detail={}, prev_hash=None, hash="h" * 64,
        )

        q = MagicMock()
        q.outerjoin.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.offset.return_value = q
        q.limit.return_value = q
        q.count.return_value = 1
        q.all.return_value = [(event, user)]
        self.mock_db.query.return_value = q

        res = self.c.get("/api/admin/user-activity")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["events"]) == 1
        ev = data["events"][0]
        assert ev["id"] == 101
        assert ev["action"] == "auth_login"
        assert ev["actor_name"] == "Target User"
        assert ev["actor_email"] == "user@tv.local"
        assert ev["actor_role"] == "owner"

    def test_user_activity_filters(self):
        q = MagicMock()
        q.outerjoin.return_value = q
        q.filter.return_value = q
        q.order_by.return_value = q
        q.offset.return_value = q
        q.limit.return_value = q
        q.count.return_value = 0
        q.all.return_value = []
        self.mock_db.query.return_value = q

        actor = uuid.uuid4()
        res = self.c.get(f"/api/admin/user-activity?action=doc_upload&actor_id={actor}&limit=20&offset=5")
        assert res.status_code == 200
        # q.filter called for ts, action, actor_id
        assert q.filter.call_count >= 2
        q.offset.assert_called_with(5)
        q.limit.assert_called_with(20)

    def test_alert_detection_logic(self):
        from app.admin_router import _detect_alerts
        db = MagicMock()
        now = datetime.now(timezone.utc)
        user_id = uuid.uuid4()
        doc_id = uuid.uuid4()

        # 1. Denials alert row
        denial_row = MagicMock(actor_id=user_id, n=8)
        # 2. Odd hour download
        odd_evt = MagicMock(actor_id=user_id, doc_id=doc_id, ts=now, action="download")
        # 3. Bulk download row
        bulk_row = MagicMock(actor_id=user_id, n=15)
        # 4. Recent grant + quick download
        grant_evt = MagicMock(id=10, target_user_id=user_id, doc_id=doc_id, ts=now - timedelta(seconds=30))
        quick_dl = MagicMock(id=11, ts=now - timedelta(seconds=10))
        # 5. Revocation + pre-access
        revoke_evt = MagicMock(id=20, doc_id=doc_id, ts=now)
        pre_access = MagicMock(id=19, actor_id=user_id, ts=now - timedelta(seconds=60))

        # Setup mock db queries for each alert check
        q = MagicMock()
        db.query.return_value = q
        q.filter.return_value = q
        q.group_by.return_value = q
        q.having.return_value = q

        # Sequence of .all() calls: denial_rows, odd_rows, bulk_rows, recent_grants, recent_revokes
        q.all.side_effect = [
            [denial_row],   # 1. many_denials
            [odd_evt],      # 2. odd_hour_download
            [bulk_row],     # 3. bulk_download
            [grant_evt],    # 4. recent_grants
            [revoke_evt],   # 5. recent_revokes
        ]
        # Sequence of .first() calls: quick_dl, pre_access
        q.first.side_effect = [
            quick_dl,       # 4. quick_dl
            pre_access,     # 5. pre_access
        ]

        alerts = _detect_alerts(db)
        alert_types = [a.alert_type for a in alerts]

        assert "many_denials" in alert_types
        assert "odd_hour_download" in alert_types
        assert "bulk_download" in alert_types
        assert "grant_then_immediate_download" in alert_types
        assert "access_before_revocation" in alert_types

