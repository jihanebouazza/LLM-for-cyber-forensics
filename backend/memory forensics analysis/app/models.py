import uuid
from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

# Helper for UUIDs to ensure compatibility if we switch to SQLite for dev
# In a real Postgres env, we might use: from sqlalchemy.dialects.postgresql import UUID
# But for generic SQLAlchemy 2.0+, we can use Uuid or String.
# For simplicity and SQLite compatibility in this MVP, we'll use String for UUIDs.
def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    
    memory_images = relationship("MemoryImage", back_populates="uploader")

class Case(Base):
    __tablename__ = "cases"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    memory_images = relationship("MemoryImage", back_populates="case")

class MemoryImage(Base):
    __tablename__ = "memory_images"

    id = Column(String, primary_key=True, default=generate_uuid)
    case_id = Column(String, ForeignKey("cases.id"))
    filename = Column(String(255))
    file_path = Column(Text)
    file_hash = Column(String(255))
    os_type = Column(String(50))
    acquired_at = Column(DateTime(timezone=True))
    uploaded_by = Column(String, ForeignKey("users.id"))
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("Case", back_populates="memory_images")
    uploader = relationship("User", back_populates="memory_images")
    volatility_results = relationship("VolatilityResult", back_populates="memory_image")
    artifacts = relationship("Artifact", back_populates="memory_image")

class VolatilityResult(Base):
    __tablename__ = "volatility_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    memory_image_id = Column(String, ForeignKey("memory_images.id"))
    module = Column(String(100))
    command = Column(Text)
    output = Column(JSON) # JSONB in Postgres, JSON in SQLite
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    memory_image = relationship("MemoryImage", back_populates="volatility_results")

class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(String, primary_key=True, default=generate_uuid)
    memory_image_id = Column(String, ForeignKey("memory_images.id"))
    type = Column(String(50)) # process / network_conn / dll / file
    name = Column(String(255))
    path = Column(Text)
    pid = Column(Integer, nullable=True)
    port = Column(Integer, nullable=True)
    state = Column(String(50), nullable=True)
    extra_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    memory_image = relationship("MemoryImage", back_populates="artifacts")
