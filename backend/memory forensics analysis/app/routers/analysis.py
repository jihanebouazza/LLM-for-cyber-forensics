import uuid
import subprocess
import sys
import json
import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db, SessionLocal

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)

# In-memory job store for status tracking
jobs = {}

def parse_and_save_artifacts(image_id: str, plugin: str, output_json: List[dict], db: Session):
    """
    Parses raw Volatility 3 JSON output and saves structured Artifacts.
    """
    if not isinstance(output_json, list):
        return # Volatility sometimes returns dict for errors or single items, we skip unique edge cases for MVP

    new_artifacts = []
    
    for item in output_json:
        # Normalize keys (Volatility JSON keys might be case-sensitive or vary)
        # pslist keys: ImageFileName, PID, PPID, Threads, Handles, CreateTime...
        
        if plugin == "windows.pslist":
            # Extract Process Info
            name = item.get("ImageFileName", "Unknown")
            pid = item.get("PID")
            ppid = item.get("PPID")
            create_time = item.get("CreateTime")
            
            # Create Artifact
            artifact = models.Artifact(
                memory_image_id=image_id,
                type="process",
                name=name,
                pid=pid,
                path=f"process://{name}", # Pseudo-path since pslist doesn't always give full path
                state="running" if item.get("ExitTime") is None else "exited",
                extra_metadata={
                    "ppid": ppid, 
                    "threads": item.get("Threads"), 
                    "handles": item.get("Handles"),
                    "create_time": create_time
                }
            )
            new_artifacts.append(artifact)
            
        elif plugin == "windows.netscan":
             # Extract Network Info
             # netscan keys: Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner
             proto = item.get("Proto", "Unknown")
             foreign_ip = item.get("ForeignAddr", "")
             foreign_port = item.get("ForeignPort")
             state = item.get("State", "UNKNOWN")
             pid = item.get("PID")
             
             artifact = models.Artifact(
                memory_image_id=image_id,
                type="network_conn",
                name=f"{proto}:{foreign_ip}:{foreign_port}",
                path=f"{item.get('LocalAddr')}:{item.get('LocalPort')} -> {foreign_ip}:{foreign_port}",
                pid=pid,
                port=foreign_port, # Using remote port as primary interest
                state=state,
                extra_metadata={
                    "protocol": proto,
                    "local_addr": item.get("LocalAddr"),
                    "local_port": item.get("LocalPort"),
                    "owner": item.get("Owner")
                }
             )
             new_artifacts.append(artifact)

    if new_artifacts:
        db.add_all(new_artifacts)
        db.commit()
        print(f"Saved {len(new_artifacts)} artifacts for {plugin}")

def run_volatility_real(job_id: str, image_id: str, plugin: str):
    db = SessionLocal()
    try:
        # 1. Get the file path
        image = db.query(models.MemoryImage).filter(models.MemoryImage.id == image_id).first()
        if not image:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["result"] = {"error": "Image not found"}
            return

        file_path = image.file_path
        
        # 2. Construct command: Use the absolute path to 'vol' script in venv
        # Assuming Windows structure: venv/Scripts/vol.exe
        vol_path = os.path.join(sys.prefix, "Scripts", "vol.exe")
        
        # Fallback for non-Windows or different venv structure if needed, but this matches the user's setup
        if not os.path.exists(vol_path):
             vol_path = os.path.join(sys.prefix, "bin", "vol") # Linux/Mac

        cmd = [vol_path, "-f", file_path, "-r", "json", plugin]
        
        # 3. Execute
        print(f"Running command: {' '.join(cmd)}")
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["result"] = {"error": process.stderr}
            print(f"Error running volatility: {process.stderr}")
            return

        # 4. Parse Output
        try:
            output_json = json.loads(process.stdout)
        except json.JSONDecodeError:
            # Fallback if text output or empty
            output_json = {"raw_output": process.stdout}

        # 5. Save Raw Results to Database
        db_result = models.VolatilityResult(
            memory_image_id=image_id,
            module=plugin,
            command=" ".join(cmd),
            output=output_json
        )
        db.add(db_result)
        db.commit()
        
        # 6. Normalize and Save Structure Artifacts
        parse_and_save_artifacts(image_id, plugin, output_json, db)

        # 7. Update Job Status
        jobs[job_id]["status"] = "completed"
        jobs[job_id]["result"] = output_json

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["result"] = {"error": str(e)}
        print(f"Exception in analysis: {e}")
    finally:
        db.close()

@router.post("/trigger", response_model=schemas.AnalysisJob)
def trigger_analysis(
    trigger: schemas.AnalysisTrigger, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "running", "result": None}
    
    # Run the real tool in background
    background_tasks.add_task(run_volatility_real, job_id, trigger.image_id, trigger.plugin_name)
    
    return schemas.AnalysisJob(job_id=job_id, status="running")

@router.get("/status/{job_id}", response_model=schemas.AnalysisJob)
def get_analysis_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = jobs[job_id]
    return schemas.AnalysisJob(job_id=job_id, status=job["status"], result=job["result"])
