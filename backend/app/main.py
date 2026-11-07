from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import cfg
from app.db import get_db
from app.auth_router import router as auth_router
from app.doc_router import router as doc_router

app = FastAPI(title=cfg.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(doc_router, prefix="/api/documents")
app.include_router(doc_router, prefix="/documents")

@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "app": cfg.app_name}

@app.get("/api/health")
def api_health(db: Session = Depends(get_db)):
    return health(db=db)
