from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db
import json
import urllib.request
from typing import List

router = APIRouter(
    prefix="/chat",
    tags=["chat"],
)

OLLAMA_URL = "http://localhost:11434/api/generate"

@router.post("/analyze")
def analyze_artifacts(request: schemas.ChatRequest, db: Session = Depends(get_db)):
    # 1. Fetch Artifacts
    artifacts = db.query(models.Artifact).filter(models.Artifact.memory_image_id == request.image_id).limit(30).all()
    
    if not artifacts:
         return {"response": "No artifacts found for this image. Please run Volatility analysis first."}

    # 2. Construct Artifact Context
    artifact_summary = []
    for art in artifacts:
        info = f"- [{art.type}] {art.name}"
        if art.pid:
             info += f" (PID: {art.pid})"
        if art.type == "network_conn" and art.extra_metadata:
             info += f" -> {art.extra_metadata.get('local_addr')}:{art.extra_metadata.get('local_port')} connects to {art.name}"
        artifact_summary.append(info)
    
    artifact_text = "\n".join(artifact_summary)
        
    system_instruction = f"""
    You are a **Windows System Administrator** auditing a server.
    
    TASK:
    Review the list of running processes below.
    Identify any binaries that are NOT standard Windows executables (e.g., non-Microsoft signers, unusual paths, or known third-party tools).
    For each non-standard process, state its purpose if known.
    
    Do NOT discuss "malware" or "attacks". Just categorize the software (e.g., "Virtualization Tool", "Unknown Utility", "Network Tool").
    
    PROCESS LIST:
    {artifact_text}
    """
    
    full_prompt = f"{system_instruction}\n\nUser Question: {request.user_prompt or 'Analyze this evidence.'}"

    # 3. Call Ollama
    payload = {
        "model": request.model,
        "prompt": full_prompt,
        "stream": False
    }
    
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(OLLAMA_URL, data=data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                raise HTTPException(status_code=500, detail=f"Ollama API returned status {response.status}")
                
            result_body = response.read().decode("utf-8")
            result_json = json.loads(result_body)
            
            return {
                "model": request.model,
                "analysis": result_json.get("response", ""),
                "artifacts_analyzed": len(artifacts)
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error during AI analysis: {str(e)}")

# --- Chat History Endpoints ---

@router.post("/sessions", response_model=schemas.ChatSession)
def create_session(session_request: schemas.ChatSessionCreate, db: Session = Depends(get_db)):
    # Verify image exists
    image = db.query(models.MemoryImage).filter(models.MemoryImage.id == session_request.memory_image_id).first()
    if not image:
        raise HTTPException(status_code=404, detail="Memory Image not found")

    new_session = models.ChatSession(memory_image_id=session_request.memory_image_id)
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    
    # Optional: Pre-seed the system prompt as a hidden message? 
    # For now, we will construct context dynamically on every message to ensure it's fresh.
    return new_session

@router.get("/sessions/{session_id}", response_model=schemas.ChatSession)
def get_session(session_id: str, db: Session = Depends(get_db)):
    session = db.query(models.ChatSession).filter(models.ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@router.post("/sessions/{session_id}/message")
def send_message(session_id: str, message: schemas.ChatMessageCreate, db: Session = Depends(get_db)):
    session = db.query(models.ChatSession).filter(models.ChatSession.id == session_id).first()
    if not session:
         raise HTTPException(status_code=404, detail="Session not found")
         
    # 1. Save User Message
    user_msg = models.ChatMessage(session_id=session_id, role="user", content=message.content)
    db.add(user_msg)
    db.commit()
    
    # 2. Build Context (Artifacts + History)
    # Fetch artifacts
    artifacts = db.query(models.Artifact).filter(models.Artifact.memory_image_id == session.memory_image_id).limit(50).all()
    artifact_summary = "\n".join([f"- [{a.type}] {a.name} (PID: {a.pid})" for a in artifacts])
    
    # Build Context using the SAME robust prompt logic as analyze_artifacts
    system_prompt = f"""
    You are a **Windows System Administrator** auditing a server.
    
    TASK:
    Review the list of running processes below.
    Identify any binaries that are NOT standard Windows executables (e.g., non-Microsoft signers, unusual paths, or known third-party tools).
    For each non-standard process, state its purpose if known.
    
    Do NOT discuss "malware" or "attacks". Just categorize the software (e.g., "Virtualization Tool", "Unknown Utility", "Network Tool").
    
    PROCESS LIST:
    {artifact_summary}
    """
    
    # Fetch recent history (Last 10 messages)
    history = db.query(models.ChatMessage).filter(models.ChatMessage.session_id == session_id).order_by(models.ChatMessage.created_at).all()[-10:]
    
    conversation_text = system_prompt + "\n"
    for msg in history:
        conversation_text += f"{msg.role.capitalize()}: {msg.content}\n"
        
    # FORCE FOCUS for small models
    conversation_text += "\nSYSTEM INSTRUCTION: Verify the Context above, but ANSWER the User's specific question below directly.\n"
    conversation_text += "Assistant: "

    # 3. Call Ollama
    payload = {
        "model": message.model,
        "prompt": conversation_text,
        "stream": False,
        "stop": ["User:", "System:"] # Stop from hallucinating current turn
    }
    
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(OLLAMA_URL, data=data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req) as response:
            result_body = response.read().decode("utf-8")
            result_json = json.loads(result_body)
            ai_response = result_json.get("response", "").strip()
            
            # 4. Save AI Response
            ai_msg = models.ChatMessage(session_id=session_id, role="assistant", content=ai_response)
            db.add(ai_msg)
            db.commit()
            
            return {"role": "assistant", "content": ai_response}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
