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

def seed_users():
    db = SessionLocal()
    created = []
    try:
        for udata in SEEDED_USERS:
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
        db.commit()
    finally:
        db.close()
    return created

if __name__ == "__main__":
    c = seed_users()
    print(f"Seed completed. Created {len(c)} users: {c}")
