import os
from app.config import cfg
from app.db import SessionLocal
from app.models import User
from app.security import hash_pw

SEEDED_USERS = [
    {
        "name": "System Administrator",
        "email": "admin@trustvault.local",
        "password": "AdminPassword123!",
        "role": "admin",
    },
    {
        "name": "Alice Vance",
        "email": "alice.owner@trustvault.local",
        "password": "AlicePassword123!",
        "role": "owner",
    },
    {
        "name": "Bob Martinez",
        "email": "bob.owner@trustvault.local",
        "password": "BobPassword123!",
        "role": "owner",
    },
    {
        "name": "Charlie Kim",
        "email": "charlie.viewer@trustvault.local",
        "password": "CharliePassword123!",
        "role": "viewer",
    },
    {
        "name": "David Chen",
        "email": "david.viewer@trustvault.local",
        "password": "DavidPassword123!",
        "role": "viewer",
    },
]

def get_seed_users():
    admin_email = os.getenv("SEED_ADMIN_EMAIL")
    admin_pw = os.getenv("SEED_ADMIN_PASSWORD")
    owner_email = os.getenv("SEED_OWNER_EMAIL")
    owner_pw = os.getenv("SEED_OWNER_PASSWORD")
    viewer_email = os.getenv("SEED_VIEWER_EMAIL")
    viewer_pw = os.getenv("SEED_VIEWER_PASSWORD")

    if admin_email and admin_pw:
        users = [
            {"name": "Admin", "email": admin_email.strip().lower(), "password": admin_pw, "role": "admin"},
        ]
        if owner_email and owner_pw:
            users.append({"name": "Owner", "email": owner_email.strip().lower(), "password": owner_pw, "role": "owner"})
        if viewer_email and viewer_pw:
            users.append({"name": "Viewer", "email": viewer_email.strip().lower(), "password": viewer_pw, "role": "viewer"})
        return users

    if cfg.env.lower() == "production":
        raise RuntimeError("Default seed credentials are prohibited in production environment!")

    return SEEDED_USERS

def seed_users():
    users_to_seed = get_seed_users()
    db = SessionLocal()
    created = []
    try:
        for udata in users_to_seed:
            existing = db.query(User).filter(User.email == udata["email"]).first()
            if not existing:
                u = User(
                    email=udata["email"],
                    name=udata["name"],
                    pw_hash=hash_pw(udata["password"]),
                    role=udata["role"],
                    is_active=True,
                    token_version=1,
                    failed_logins=0,
                )
                db.add(u)
                created.append(udata["email"])
            else:
                if os.getenv("SEED_ADMIN_PASSWORD") or os.getenv("SEED_OWNER_PASSWORD") or os.getenv("SEED_VIEWER_PASSWORD"):
                    existing.pw_hash = hash_pw(udata["password"])
                    existing.is_active = True
                    created.append(udata["email"])
        db.commit()
    finally:
        db.close()
    return created

if __name__ == "__main__":
    c = seed_users()
    print(f"Seed completed. Created {len(c)} users: {c}")
