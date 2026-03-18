import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker


DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vapt:vaptpass@db:5432/vaptdb")
SQL_ECHO = os.getenv("SQL_ECHO", "false").lower() == "true"

engine = create_engine(DATABASE_URL, echo=SQL_ECHO, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
