from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db

router = APIRouter(
    prefix="/volatility_results",
    tags=["volatility_results"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.VolatilityResult)
def create_volatility_result(result: schemas.VolatilityResultCreate, db: Session = Depends(get_db)):
    db_result = models.VolatilityResult(**result.model_dump())
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return db_result

@router.get("/{image_id}", response_model=List[schemas.VolatilityResult])
def read_volatility_results(image_id: str, db: Session = Depends(get_db)):
    results = db.query(models.VolatilityResult).filter(models.VolatilityResult.memory_image_id == image_id).all()
    return results
