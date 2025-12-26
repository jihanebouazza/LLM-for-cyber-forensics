from pydantic import BaseModel, Field
from typing import Optional,List
from datetime import datetime
from uuid import UUID


class NetworkFlowInput(BaseModel):
    timestamp_start: datetime
    timestamp_end: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    action: str
    bytes_in: int
    bytes_out: int
    sensor: str


class LogInput(BaseModel):
    timestamp: datetime
    log_level: str
    raw_text: str
    category: str