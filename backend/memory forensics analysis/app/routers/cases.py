from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db

router = APIRouter(
    prefix="/cases",
    tags=["cases"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Case)
def create_case(case: schemas.CaseCreate, db: Session = Depends(get_db)):
    db_case = models.Case(**case.model_dump())
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case

@router.get("/{case_id}/timeline", response_model=List[schemas.CaseTimelineItem])
def get_case_timeline(case_id: str, db: Session = Depends(get_db)):
    # 1. Find all memory images for this case
    images = db.query(models.MemoryImage).filter(models.MemoryImage.case_id == case_id).all()
    
    if not images:
        return []

    image_ids = [img.id for img in images]
    
    # 2. Fetch all artifacts for these images
    artifacts = db.query(models.Artifact).filter(models.Artifact.memory_image_id.in_(image_ids)).order_by(models.Artifact.created_at).all()
    
    timeline = []
    for art in artifacts:
        # 3. Convert to TimelineItem schema
        timestamp = art.extra_metadata.get("create_time") if art.extra_metadata else None
        
        # Fallback to DB creation time if artifact specific timestamp is missing
        if not timestamp:
            timestamp = art.created_at
            
        description = f"Artifact found: {art.name} ({art.type})"
        if art.type == "process":
            description = f"Process Started: {art.name} (PID: {art.pid})"
        elif art.type == "network_conn":
            description = f"Network Connection: {art.name} ({art.state})"

        item = schemas.CaseTimelineItem(
            timestamp=timestamp,
            type=art.type,
            description=description,
            artifact_id=art.id
        )
        timeline.append(item)
    
    return timeline

@router.post("/{case_id}/report")
def generate_report(case_id: str, request: schemas.CaseReportRequest, db: Session = Depends(get_db)):
    # Generate a report based on findings
    return {
        "case_id": case_id,
        "format": request.format,
        "content": f"# Report for Case {case_id}\n\n## Summary\nNo critical threats found (Mock Report)."
    }
