from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db

router = APIRouter(
    prefix="/memory_images",
    tags=["memory_images"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.MemoryImage)
def create_memory_image(memory_image: schemas.MemoryImageCreate, db: Session = Depends(get_db)):
    # Check if case exists, if not create a dummy one for now or error?
    # For MVP, we assume IDs are valid or we let FK constraint fail.
    # But to make it easier, let's just try to insert.
    db_memory_image = models.MemoryImage(**memory_image.model_dump())
    db.add(db_memory_image)
    db.commit()
    db.refresh(db_memory_image)
    return db_memory_image

@router.get("/", response_model=List[schemas.MemoryImage])
def read_memory_images(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    memory_images = db.query(models.MemoryImage).offset(skip).limit(limit).all()
    return memory_images

@router.get("/{image_id}", response_model=schemas.MemoryImage)
def read_memory_image(image_id: str, db: Session = Depends(get_db)):
    db_memory_image = db.query(models.MemoryImage).filter(models.MemoryImage.id == image_id).first()
    if db_memory_image is None:
        raise HTTPException(status_code=404, description="Memory image not found")
    return db_memory_image
