import os
import re
import json
import uuid
from datetime import datetime, timezone
from uuid import UUID
import httpx
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from app.models import Document, Grant, User, AuditEvent
from app.config import cfg

# In-memory store for pending suggestions
_SUGGESTIONS: dict[str, dict] = {}

def get_candidates(db: Session, doc: Document, owner: User) -> list[User]:
    # Active users except the owner
    try:
        users = db.query(User).filter(User.id != doc.owner_id, User.is_active == True).all()
    except Exception:
        users = [u for u in db.query(User).all() if u.id != doc.owner_id and getattr(u, "is_active", True)]

    # Filter out users who already have active grants on this document
    now = datetime.now(timezone.utc)
    try:
        active_grants = (
            db.query(Grant)
            .filter(
                Grant.doc_id == doc.id,
                Grant.revoked_at.is_(None),
                or_(Grant.expires_at.is_(None), Grant.expires_at > now),
            )
            .all()
        )
        active_user_ids = {g.user_id for g in active_grants}
    except Exception:
        active_user_ids = set()

    return [u for u in users if u.id not in active_user_ids]


def _words(text: str | None) -> set[str]:
    if not text:
        return set()
    return set(re.findall(r"\w+", text.lower()))


def heuristic_suggestions(db: Session, doc: Document, owner: User, candidates: list[User]) -> list[dict]:
    results = []
    doc_cat = (doc.category or "").strip().lower()
    doc_words = _words(doc.category)

    for cand in candidates:
        score = 0
        reasons = []
        perm_votes = {"read": 0, "edit": 0}

        try:
            # Grants for this candidate
            grants = db.query(Grant).filter(Grant.user_id == cand.id).all()
        except Exception:
            grants = []

        same_cat_cnt = 0
        owner_same_cat_cnt = 0
        sim_cat_cnt = 0
        owner_other_cnt = 0

        for g in grants:
            g_doc = None
            try:
                g_doc = db.query(Document).filter(Document.id == g.doc_id).first()
            except Exception:
                pass

            g_perm = g.perm if g.perm in ("read", "edit") else "read"
            g_cat = (g_doc.category or "").strip().lower() if g_doc else ""

            if g_cat and g_cat == doc_cat:
                same_cat_cnt += 1
                perm_votes[g_perm] += 1
                if g.granted_by == owner.id:
                    owner_same_cat_cnt += 1
            elif g_cat and doc_words and (doc_words & _words(g_cat)):
                sim_cat_cnt += 1
                perm_votes[g_perm] += 1
            elif g.granted_by == owner.id:
                owner_other_cnt += 1
                perm_votes[g_perm] += 1

        if owner_same_cat_cnt > 0:
            score += 20 + owner_same_cat_cnt * 5
            reasons.append(f"Granted {owner_same_cat_cnt} '{doc.category}' doc(s) previously by you")
        elif same_cat_cnt > 0:
            score += 15 + same_cat_cnt * 4
            reasons.append(f"Granted {same_cat_cnt} doc(s) in category '{doc.category}'")

        if sim_cat_cnt > 0:
            score += 10 + sim_cat_cnt * 2
            reasons.append(f"Granted {sim_cat_cnt} doc(s) in similar categories")

        if owner_other_cnt > 0 and not owner_same_cat_cnt:
            score += 8 + owner_other_cnt * 2
            reasons.append(f"Collaborated with you on {owner_other_cnt} other doc(s)")

        if not reasons:
            score = 1
            reasons.append(f"Active member (role: {cand.role})")

        rec_perm = "edit" if perm_votes["edit"] > perm_votes["read"] else "read"

        results.append({
            "user_id": str(cand.id),
            "email": cand.email,
            "user_email": cand.email,
            "name": cand.name,
            "user_name": cand.name,
            "suggested_perm": rec_perm,
            "perm": rec_perm,
            "reason": "; ".join(reasons),
            "_score": score,
        })

    results.sort(key=lambda x: x["_score"], reverse=True)
    return results


def call_anthropic_sharing_assistant(
    api_key: str,
    doc_name: str,
    doc_category: str,
    doc_description: str | None,
    candidates: list[User],
) -> list[dict] | None:
    # Strictly passes only doc name/category/description and candidate info
    # NEVER file contents
    cand_info = [{"email": u.email, "name": u.name, "role": u.role} for u in candidates]
    prompt = (
        f"You are a document sharing assistant. Recommend which of the following candidate users "
        f"should be granted access to this document based strictly on the document metadata and candidate profiles.\n"
        f"Document Name: {doc_name}\n"
        f"Category: {doc_category}\n"
        f"Description: {doc_description or 'None'}\n\n"
        f"Candidates:\n{json.dumps(cand_info, indent=2)}\n\n"
        f"Return ONLY a JSON array of objects with keys: 'email', 'perm' ('read' or 'edit'), and 'reason'. "
        f"Do not include markdown fences or any other text."
    )

    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 512,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None

        body = resp.json()
        raw_text = body.get("content", [{}])[0].get("text", "").strip()
        # Strip code block fences if present
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$", "", raw_text)
        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    return None


def generate_sharing_suggestions(db: Session, doc: Document, owner: User) -> tuple[UUID, list[dict]]:
    candidates = get_candidates(db, doc, owner)
    heuristic_list = heuristic_suggestions(db, doc, owner, candidates)

    api_key = os.environ.get("ANTHROPIC_API_KEY") or getattr(cfg, "anthropic_api_key", None)
    if api_key and candidates:
        llm_recs = call_anthropic_sharing_assistant(
            api_key=api_key,
            doc_name=doc.name,
            doc_category=doc.category,
            doc_description=doc.description,
            candidates=candidates,
        )
        if llm_recs:
            by_email = {r["email"].lower(): r for r in llm_recs if "email" in r}
            for h in heuristic_list:
                rec = by_email.get(h["email"].lower())
                if rec:
                    if rec.get("perm") in ("read", "edit"):
                        h["suggested_perm"] = rec["perm"]
                        h["perm"] = rec["perm"]
                    if rec.get("reason"):
                        h["reason"] = f"[AI] {rec['reason']}"
                    h["_score"] += 50
            heuristic_list.sort(key=lambda x: x["_score"], reverse=True)

    # Clean internal score
    cleaned = []
    for h in heuristic_list:
        item = {k: v for k, v in h.items() if not k.startswith("_")}
        cleaned.append(item)

    sid = uuid.uuid4()
    _SUGGESTIONS[str(sid)] = {
        "sid": str(sid),
        "doc_id": str(doc.id),
        "owner_id": str(owner.id),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "suggestions": cleaned,
        "status": "pending",
    }

    return sid, cleaned


def get_suggestion_session(db: Session, sid: str | UUID, doc_id: str | UUID) -> dict | None:
    sid_str = str(sid)
    doc_id_str = str(doc_id)

    # Check memory first
    sess = _SUGGESTIONS.get(sid_str)
    if sess and sess.get("doc_id") == doc_id_str:
        return sess

    # Fallback to audit trail
    try:
        evt = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action == "suggest_access",
                AuditEvent.doc_id == UUID(doc_id_str),
                AuditEvent.outcome == "allowed",
            )
            .order_by(AuditEvent.id.desc())
            .all()
        )
        for e in evt:
            if isinstance(e.detail, dict) and e.detail.get("sid") == sid_str:
                recovered = {
                    "sid": sid_str,
                    "doc_id": doc_id_str,
                    "owner_id": str(e.actor_id),
                    "created_at": e.ts.isoformat(),
                    "suggestions": e.detail.get("suggestions", []),
                    "status": "pending",
                }
                _SUGGESTIONS[sid_str] = recovered
                return recovered
    except Exception:
        pass

    return None


def evaluate_decision(orig_suggestions: list[dict], picked_grants: list[dict], explicit_action: str | None = None) -> str:
    if explicit_action:
        act = explicit_action.strip().lower()
        if act in ("accepted", "accept"):
            return "accepted"
        if act in ("rejected", "reject"):
            return "rejected"
        if act in ("modified", "modify"):
            return "modified"

    if not picked_grants:
        return "rejected"

    orig_set = {(s.get("email", "").lower(), s.get("perm", "read")) for s in orig_suggestions}
    picked_set = {(p.get("user_email", "").lower(), p.get("perm", "read")) for p in picked_grants}

    if orig_set and picked_set == orig_set:
        return "accepted"
    return "modified"
