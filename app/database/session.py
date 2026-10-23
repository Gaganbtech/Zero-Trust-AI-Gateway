from typing import Generator
from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

Base = declarative_base()

_current_url = None
_current_engine = None
_current_sessionmaker = None


def get_engine() -> Engine:
    global _current_url, _current_engine, _current_sessionmaker
    if _current_engine is None or _current_url != settings.DATABASE_URL:
        _current_url = settings.DATABASE_URL
        connect_args = {}
        if _current_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _current_engine = create_engine(
            _current_url,
            connect_args=connect_args,
            echo=settings.DATABASE_ECHO,
            pool_pre_ping=True,
        )
        _current_sessionmaker = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=_current_engine
        )
    return _current_engine


def SessionLocal() -> Session:
    get_engine()
    return _current_sessionmaker()


class EngineProxy:
    def __getattr__(self, name):
        return getattr(get_engine(), name)


engine = EngineProxy()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
