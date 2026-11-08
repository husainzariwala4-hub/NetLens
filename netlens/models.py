from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CaptureRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=512)


class PacketExplanation(BaseModel):
    title: str
    description: str
    limitation: str


class PacketSummary(BaseModel):
    id: int
    session_id: str
    timestamp: datetime
    source: str | None = None
    destination: str | None = None
    protocol: str
    transport_protocol: str | None = None
    length: int
    source_port: int | None = None
    destination_port: int | None = None
    source_mac: str | None = None
    destination_mac: str | None = None
    ttl: int | None = None
    tcp_flags: str | None = None
    event_type: str | None = None
    explanation: PacketExplanation | None = None


class CaptureStatus(BaseModel):
    state: Literal["idle", "starting", "running", "stopping", "error"]
    interface: str | None = None
    session_id: str | None = None
    captured: int = 0
    dropped: int = 0
    error: str | None = None
