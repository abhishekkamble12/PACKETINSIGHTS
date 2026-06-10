from __future__ import annotations

from sqlalchemy import create_engine, ForeignKey, String, Integer, Float
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Mapped, mapped_column

Base = declarative_base()


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    packet_size: Mapped[int] = mapped_column(Integer, nullable=False)
    flow_id: Mapped[int | None] = mapped_column(ForeignKey("flows.id"), nullable=True)

    flow: Mapped[Flow | None] = relationship(back_populates="packets")
    dns_queries: Mapped[list[DNSQuery]] = relationship(
        back_populates="packet", cascade="all, delete-orphan"
    )
    http_requests: Mapped[list[HTTPRequest]] = relationship(
        back_populates="packet", cascade="all, delete-orphan"
    )
    tls_sessions: Mapped[list[TLSSession]] = relationship(
        back_populates="packet", cascade="all, delete-orphan"
    )


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    src_ip: Mapped[str] = mapped_column(String, nullable=False)
    dst_ip: Mapped[str] = mapped_column(String, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String, nullable=False)
    packet_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[float] = mapped_column(Float, nullable=False)
    duration: Mapped[float] = mapped_column(Float, nullable=False)

    packets: Mapped[list[Packet]] = relationship(
        back_populates="flow", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[Alert]] = relationship(
        back_populates="flow", cascade="all, delete-orphan"
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)
    rule_name: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    flow_id: Mapped[int | None] = mapped_column(ForeignKey("flows.id"), nullable=True)

    flow: Mapped[Flow | None] = relationship(back_populates="alerts")


class DNSQuery(Base):
    __tablename__ = "dns_queries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    packet_id: Mapped[int] = mapped_column(ForeignKey("packets.id"), nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False)
    query_type: Mapped[str] = mapped_column(String, nullable=False, default="A")

    packet: Mapped[Packet] = relationship(back_populates="dns_queries")


class HTTPRequest(Base):
    __tablename__ = "http_requests"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    packet_id: Mapped[int] = mapped_column(ForeignKey("packets.id"), nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)

    packet: Mapped[Packet] = relationship(back_populates="http_requests")


class TLSSession(Base):
    __tablename__ = "tls_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    packet_id: Mapped[int] = mapped_column(ForeignKey("packets.id"), nullable=False)
    sni: Mapped[str] = mapped_column(String, nullable=False)
    tls_version: Mapped[str | None] = mapped_column(String, nullable=True)

    packet: Mapped[Packet] = relationship(back_populates="tls_sessions")


def get_engine(db_path: str):
    """Returns a SQLAlchemy engine for the specified SQLite database path."""
    return create_engine(f"sqlite:///{db_path}")


def init_db(db_path: str) -> None:
    """Initializes the database schema."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)


def get_session_factory(db_path: str) -> sessionmaker:
    """Returns a sessionmaker configured for the specified SQLite database path."""
    engine = get_engine(db_path)
    return sessionmaker(bind=engine)
