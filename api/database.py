"""database.py - SQLite database setup via SQLAlchemy"""
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "webscan.db")
DATABASE_URL = f"sqlite:///{os.path.abspath(DB_PATH)}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id          = Column(Integer, primary_key=True, index=True)
    target      = Column(String, nullable=False)
    status      = Column(String, default="pending")   # pending/running/done/failed
    started_at  = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration    = Column(Float, nullable=True)        # seconds
    total_vulns = Column(Integer, default=0)
    critical    = Column(Integer, default=0)
    high        = Column(Integer, default=0)
    medium      = Column(Integer, default=0)
    low         = Column(Integer, default=0)
    risk_score  = Column(Integer, default=0)
    raw_count   = Column(Integer, default=0)
    options     = Column(Text, default="{}")          # JSON of scan options
    error_msg   = Column(Text, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id          = Column(Integer, primary_key=True, index=True)
    scan_id     = Column(Integer, nullable=False, index=True)
    type        = Column(String)
    severity    = Column(String)
    url         = Column(String)
    parameter   = Column(String, nullable=True)
    payload     = Column(Text, nullable=True)
    evidence    = Column(Text, nullable=True)
    confidence  = Column(Float, default=0.75)
    cvss_score  = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    cwe         = Column(String, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()