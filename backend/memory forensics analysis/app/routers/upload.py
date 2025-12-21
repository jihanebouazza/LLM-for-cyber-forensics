import shutil
import os
from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List

router = APIRouter(
    prefix="/upload",
    tags=["upload"],
)

UPLOAD_DIR = "d:/memory_api/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@router.post("/")
def upload_memory_dump(file: UploadFile = File(...)):
    """
    Upload a memory dump file. 
    In a real production scenario with 16GB+ files, we would use chunked uploads 
    or presigned URLs to S3/Blob Storage.
    """
    try:
        file_location = f"{UPLOAD_DIR}/{file.filename}"
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
            
        return {"info": f"file '{file.filename}' saved at '{file_location}'"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save file: {str(e)}")
