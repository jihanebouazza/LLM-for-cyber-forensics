from typing import List, Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel

# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: str
    
    class Config:
        from_attributes = True

# --- Case Schemas ---
class CaseBase(BaseModel):
    name: str
    description: Optional[str] = None

class CaseCreate(CaseBase):
    pass

class Case(CaseBase):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Memory Image Schemas ---
class MemoryImageBase(BaseModel):
    filename: str
    file_path: str
    file_hash: str
    os_type: str
    acquired_at: datetime
    case_id: str
    uploaded_by: str

class MemoryImageCreate(MemoryImageBase):
    pass

class MemoryImage(MemoryImageBase):
    id: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

# --- Volatility Result Schemas ---
class VolatilityResultBase(BaseModel):
    module: str
    command: str
    output: Any # JSON

class VolatilityResultCreate(VolatilityResultBase):
    memory_image_id: str

class VolatilityResult(VolatilityResultBase):
    id: str
    memory_image_id: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Artifact Schemas ---
class ArtifactBase(BaseModel):
    type: str
    name: str
    path: str
    pid: Optional[int] = None
    port: Optional[int] = None
    state: Optional[str] = None
    extra_metadata: Optional[Dict[str, Any]] = None

class ArtifactCreate(ArtifactBase):
    memory_image_id: str

class Artifact(ArtifactBase):
    id: str
    memory_image_id: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Analysis Schemas ---
class AnalysisTrigger(BaseModel):
    image_id: str
    plugin_name: str
    parameters: Optional[Dict[str, Any]] = {}

class AnalysisJob(BaseModel):
    job_id: str
    status: str
    result: Optional[Any] = None

# --- Case Intelligence Schemas ---
class CaseTimelineItem(BaseModel):
    timestamp: datetime
    type: str
    description: str
    artifact_id: str

class CaseReportRequest(BaseModel):
    format: str = "markdown" # or pdf
    include_sections: List[str] = ["summary", "timeline", "findings"]
