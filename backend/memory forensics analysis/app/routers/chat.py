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
    Review the list of running processes below and answer the User's query directly.
    Identify any binaries that are NOT standard Windows executables (e.g., non-Microsoft signers, unusual paths, or known third-party tools).
    For each non-standard process, state its purpose if known.
    
    GUIDELINES:
    - Respond directly to the user. 
    - Do NOT narrate your thought process (e.g., avoid "The user is asking...").
    - Do NOT discuss "malware" or "attacks". Just categorize the software.
    - Keep your response professional and concise.
    
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
    Review the list of running processes below and respond to the conversation.
    Identify any binaries that are NOT standard Windows executables (e.g., non-Microsoft signers, unusual paths, or known third-party tools).
    
    GUIDELINES:
    - ALWAYS speak directly to the user.
    - NEVER start your response with "The user is asking..." or similar meta-narrative.
    - Do NOT discuss "malware" or "attacks". Just categorize the software.
    
    PROCESS LIST:
    {artifact_summary}
    """
    
    # Fetch recent history (Last 10 messages)
    history = db.query(models.ChatMessage).filter(models.ChatMessage.session_id == session_id).order_by(models.ChatMessage.created_at).all()[-10:]
    
    conversation_text = system_prompt + "\n"
    for msg in history:
        conversation_text += f"{msg.role.capitalize()}: {msg.content}\n"
        
    # FORCE FOCUS for small models
    conversation_text += "\nSYSTEM INSTRUCTION: Provide a direct answer to the user's latest query using the context above. Do not repeat the question.\n"
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


import httpx
import logging

# Configure logging to track AI behavior
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.post("/analyze/structured", response_model=schemas.StructuredAnalysisResponse)
async def analyze_artifacts_structured(request: schemas.ChatRequest, db: Session = Depends(get_db)):
    # 1. Fetch & Filter Artifacts
    # Note: We filter for "suspicious" looking things first to save tokens
    artifacts = db.query(models.Artifact).filter(
        models.Artifact.memory_image_id == request.image_id
    ).limit(10).all()

    if not artifacts:
        return schemas.StructuredAnalysisResponse(
            image_id=request.image_id,
            model=request.model,
            verdict="Inconclusive",
            confidence_score=0.0,
            suspicious_items=[],
            full_inventory=[],
            summary="No artifacts found.",
            artifacts_analyzed=0
        )

    # 2. Build a Context-Aware Forensic Prompt
    summary_lines = []
    types = [a.type for a in artifacts]
    is_mostly_files = types.count("file") > len(types) / 2
    is_mostly_procs = types.count("process") > len(types) / 2

    for a in artifacts:
        identifier = f"PID: {a.pid}" if a.pid else f"Offset: {a.offset}"
        summary_lines.append(f"{identifier} | Name/Path: {a.name} | Type: {a.type}")
    artifact_summary = "\n".join(summary_lines)

    # Dynamic Reasoning instructions
    if is_mostly_files:
        reasoning_instructions = """
    1. NAME/PATH: Is it a standard Windows path? Misspelled? Does the filename look like a random GUID (e.g., {7B29...})?
    2. ENTROPY: Does the name have high randomness (alphabets and numbers mixed)?
    3. LOCATION: Is it in a suspicious directory (e.g., \\Users\\Public\\, \\Temp\\, \\System32\\ randomly named files)?
    4. ANOMALY: Why would this be flagged in a memory dump?
        """.strip()
    elif is_mostly_procs:
        reasoning_instructions = """
    1. NAME: Is it standard Windows? Is it misspelled? Does it look random (entropy)?
    2. PID: Is it appropriate for a system service? (e.g., low PIDs for core services).
    3. HIERARCHY: Does it belong in the 'System' or 'User' category?
    4. ANOMALY: Are there any red flags (e.g., svchost.exe NOT in System32)?
        """.strip()
    else:
        reasoning_instructions = """
    1. NAME/PATH: Analyze for misspelling, random strings (entropy), or impersonation.
    2. IDENTIFIER: Check if the PID/Offset is logical for this evidence type.
    3. CATEGORY: Classify as System, Persistence, Stealth, or Network.
    4. ANOMALY: Identify why this specific artifact stands out as suspicious.
        """.strip()

    system_instruction = f"""
    You are a Senior Forensic Analyst. Perform a deep "Chain-of-Thought" analysis on the following evidence.
    
    EVIDENCE:
    {artifact_summary}

    PHASE 1: FORENSIC REASONING (Think out loud)
    For each item, evaluate:
    {reasoning_instructions}

    PHASE 2: STRUCTURED JSON
    After your reasoning, provide the final assessment in a SINGLE JSON block starting with '```json' and ending with '```'.
    If the evidence is CLEAN, be 100% definitive in your summary.
    IMPORTANT: Ensure strictly valid JSON syntax. Every list item and key-value pair MUST be separated by a comma. Use DOUBLE QUOTES only for strings.
    
    The JSON MUST follow this structure:
    {{
      "verdict": "Clean" | "Suspicious" | "Infected",
      "confidence_score": float,
      "suspicious_items": [
        {{ "pid": int, "offset": int, "name": "str", "threat_level": "Low"|"Medium"|"High", "reason": "str", "category": "str" }}
      ],
      "full_inventory": [...all items...],
      "summary": "Strictly factual 2-sentence summary."
    }}
    """

    # 3. Call Ollama (Removing 'format': 'json' to allow Phase 1 text reasoning)
    payload = {
        "model": request.model,
        "prompt": system_instruction,
        "stream": False,
        "options": {
            "temperature": 0.1, 
            "seed": 42
        }
    }

    try:
        async with httpx.AsyncClient(timeout=500.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)

            if response.status_code != 200:
                logger.error(f"Ollama error: {response.status_code}")
                raise HTTPException(status_code=500, detail=f"Ollama returned {response.status_code}")

            result = response.json()
            ai_raw_content = result.get("response", "{}")
            
            # --- EXTRACT JSON FROM CHAIN-OF-THOUGHT ---
            # Small models will write reasoning first, then the JSON.
            # We look for the JSON block markers.
            import re
            json_match = re.search(r"```json\s*(\{.*?\})\s*```", ai_raw_content, re.DOTALL)
            if not json_match:
                # Fallback: find the first { and last }
                json_match = re.search(r"(\{.*?\})", ai_raw_content, re.DOTALL)
            
            if json_match:
                ai_json_str = json_match.group(1)
            else:
                logger.error(f"AI failed to produce JSON block: {ai_raw_content}")
                raise HTTPException(status_code=500, detail="AI reasoning completed but no JSON block found.")

            def repair_json(s):
                """Attempt to fix common hallucinated JSON errors from small models."""
                s = s.strip()
                # Remove trailing commas in lists/objects
                s = re.sub(r',\s*([\]}])', r'\1', s)
                # Ensure it starts and ends with brackets
                if not s.startswith('{'): s = '{' + s
                if not s.endswith('}'): s = s + '}'
                return s

            try:
                ai_data = json.loads(ai_json_str)
            except json.JSONDecodeError:
                try:
                    repaired = repair_json(ai_json_str)
                    ai_data = json.loads(repaired)
                except Exception as je:
                    logger.error(f"Failed to parse AI JSON even after repair: {ai_json_str}")
                    raise HTTPException(status_code=500, detail=f"AI returned invalid JSON format: {str(je)}")

            # 4. Forensic Consistency & Brain API Compatibility Layer
            HARDCODED_SAFE_LIST = [
                "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", 
                "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", 
                "lsm.exe", "psxss.exe"
            ]

            # 1. Map AI findings into a lookup table for speed
            ai_findings = {}
            for item in ai_data.get("suspicious_items", []) + ai_data.get("full_inventory", []):
                pid = item.get("pid")
                offset = item.get("offset")
                key = f"p:{pid}" if pid else f"o:{offset}"
                ai_findings[key] = item

            # 2. Reconstruct the REAL inventory from DB artifacts (prevents AI truncation)
            sanitized_full = []
            for art in artifacts:
                key = f"p:{art.pid}" if art.pid else f"o:{art.offset}"
                finding = ai_findings.get(key, {})
                
                name_raw = str(art.name).lower()
                is_standard = name_raw in HARDCODED_SAFE_LIST or art.pid == 4
                
                # Base values
                level = str(finding.get("threat_level", "Low"))
                category = str(finding.get("category", "System" if is_standard else "Unknown"))
                reason = str(finding.get("reason", "Mainstream system component." if is_standard else "N/A"))
                
                # Enforce safety guard: Standard processes are ALWAYS low threat
                if is_standard:
                    level = "Low"
                    category = "System"

                if level not in ["Low", "Medium", "High"]: level = "Low"

                sanitized_full.append({
                    "pid": art.pid,
                    "offset": art.offset,
                    "name": art.name,
                    "threat_level": level,
                    "reason": reason,
                    "category": category,
                    "metadata": art.extra_metadata or {}
                })
            
            # 3. Extract actually suspicious items for the summary list
            sanitized_suspicious = [i for i in sanitized_full if i["threat_level"] in ["Medium", "High"]]

            # 4. --- LOGICAL CONSENSUS OVERRIDE ---
            verdict = str(ai_data.get("verdict", "Inconclusive"))
            summary = str(ai_data.get("summary", "Analysis completed."))

            if len(sanitized_suspicious) > 0:
                if verdict == "Clean": verdict = "Suspicious"
                if "no suspicious" in summary.lower() or "completed" in summary.lower():
                    summary = f"Forensic analysis detected {len(sanitized_suspicious)} suspicious items requiring review."
            else:
                verdict = "Clean"
                summary = "The analyzed artifacts are legitimate Windows components. No malicious indicators were detected."

            # Robust confidence score
            conf_raw = ai_data.get("confidence_score", 0.5)
            try:
                confidence = float(str(conf_raw)) if str(conf_raw).replace(".", "", 1).isdigit() else 0.5
            except:
                confidence = 0.5

            return {
                "image_id": request.image_id,
                "model": request.model,
                "verdict": verdict,
                "confidence_score": confidence,
                "analysis_type": "memory_forensics",
                "suspicious_items": sanitized_suspicious,
                "full_inventory": sanitized_full,
                "summary": summary,
                "artifacts_analyzed": len(artifacts)
            }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_msg = f"{type(e).__name__}: {str(e)}"
        logger.error(f"Analysis failed: {error_msg}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal Analysis Error: {error_msg}")

