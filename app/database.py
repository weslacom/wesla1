import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL")
# Supabase session pooler (5432) has a small client cap; Vercel serverless
# instances must use the transaction pooler (6543) to avoid exhausting it.
if DATABASE_URL and os.getenv("VERCEL") == "1" and ".pooler.supabase.com" in DATABASE_URL and ":5432" in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace(":5432", ":6543", 1)
if not DATABASE_URL:
    if os.getenv("VERCEL") == "1":
        raise RuntimeError("DATABASE_URL must be configured in Vercel before Wesla can start.")
    DATABASE_URL = "sqlite:///./wesla.db"

# The project installs psycopg v3; make SQLAlchemy use that driver explicitly.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine_options = {"connect_args": connect_args, "pool_pre_ping": True}
if not DATABASE_URL.startswith("sqlite"):
    # Keep the application pool bounded. Tune these via Railway variables only
    # after checking the Supabase connection limit and the number of app replicas.
    # Vercel runs short-lived serverless instances; bound each local connection pool.
    on_vercel = os.getenv("VERCEL") == "1"
    engine_options.update({
        # Keep one connection per warm serverless instance. Transaction pooling
        # on Supabase port 6543 handles multiplexing across Vercel instances.
        "pool_size": max(1, int(os.getenv("DB_POOL_SIZE", "1" if on_vercel else "5"))),
        "max_overflow": max(0, int(os.getenv("DB_MAX_OVERFLOW", "0" if on_vercel else "5"))),
        "pool_timeout": max(5, int(os.getenv("DB_POOL_TIMEOUT", "10" if on_vercel else "20"))),
        "pool_recycle": max(300, int(os.getenv("DB_POOL_RECYCLE", "600" if on_vercel else "1800"))),
        "pool_use_lifo": True,
        "connect_args": {"connect_timeout": 10},
    })

engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
