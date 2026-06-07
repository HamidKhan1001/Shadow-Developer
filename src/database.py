"""
Local SQLite database — persists every audit result so you can
browse history, replay demos, and show a live audit log.

Uses SQLAlchemy 2.0 async with aiosqlite.
"""
import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import String, Text, DateTime, Integer, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Store the DB file in the project root
DB_PATH = Path(__file__).parent.parent / "shadow_dev.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AuditRecord(Base):
    """Persisted audit result row."""
    __tablename__ = "audit_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    project_id: Mapped[str] = mapped_column(String(128))
    author: Mapped[str] = mapped_column(String(128), default="anonymous")
    branch: Mapped[str] = mapped_column(String(128), default="main")
    status: Mapped[str] = mapped_column(String(32))
    prompt_summary: Mapped[str] = mapped_column(Text)
    conflicts_json: Mapped[str] = mapped_column(Text, default="[]")
    tests_json: Mapped[str] = mapped_column(Text, default="[]")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


async def init_db() -> None:
    """Create tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def save_audit(record: AuditRecord) -> None:
    async with AsyncSessionLocal() as session:
        session.add(record)
        await session.commit()


async def get_audit(audit_id: str) -> AuditRecord | None:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AuditRecord).where(AuditRecord.audit_id == audit_id)
        )
        return result.scalar_one_or_none()


async def list_audits(limit: int = 50) -> list[AuditRecord]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AuditRecord).order_by(AuditRecord.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())
