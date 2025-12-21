from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db

router = APIRouter(
    prefix="/artifacts",
    tags=["artifacts"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Artifact)
def create_artifact(artifact: schemas.ArtifactCreate, db: Session = Depends(get_db)):
    db_artifact = models.Artifact(**artifact.model_dump())
    db.add(db_artifact)
    db.commit()
    db.refresh(db_artifact)
    return db_artifact

@router.get("/{image_id}", response_model=List[schemas.Artifact])
def read_artifacts(image_id: str, db: Session = Depends(get_db)):
    artifacts = db.query(models.Artifact).filter(models.Artifact.memory_image_id == image_id).all()
    return artifacts
