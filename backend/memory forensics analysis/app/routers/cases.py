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
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from fastapi.responses import FileResponse
    import os
    import tempfile
    
    # 1. Fetch case details
    case = db.query(models.Case).filter(models.Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # 2. Fetch all memory images for this case
    images = db.query(models.MemoryImage).filter(models.MemoryImage.case_id == case_id).all()
    
    # 3. Fetch all artifacts from those images
    image_ids = [img.id for img in images]
    artifacts = db.query(models.Artifact).filter(
        models.Artifact.memory_image_id.in_(image_ids)
    ).order_by(models.Artifact.created_at).all() if image_ids else []
    
    # 4. Generate PDF
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf_path = temp_file.name
    temp_file.close()
    
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=1  # Center
    )
    story.append(Paragraph(f"Forensic Analysis Report", title_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # Case Information
    story.append(Paragraph(f"<b>Case:</b> {case.name}", styles['Heading2']))
    story.append(Paragraph(f"<b>Description:</b> {case.description or 'N/A'}", styles['Normal']))
    story.append(Paragraph(f"<b>Created:</b> {case.created_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))
    
    # Memory Images Section
    story.append(Paragraph("<b>Memory Images Analyzed:</b>", styles['Heading2']))
    if images:
        for img in images:
            story.append(Paragraph(f"• {img.filename} ({img.os_type})", styles['Normal']))
    else:
        story.append(Paragraph("No memory images associated with this case.", styles['Normal']))
    story.append(Spacer(1, 0.3 * inch))
    
    # Artifacts Summary
    story.append(Paragraph("<b>Artifacts Discovered:</b>", styles['Heading2']))
    story.append(Paragraph(f"Total: {len(artifacts)} artifacts", styles['Normal']))
    
    # Count by type
    artifact_counts = {}
    for art in artifacts:
        artifact_counts[art.type] = artifact_counts.get(art.type, 0) + 1
    
    if artifact_counts:
        story.append(Spacer(1, 0.1 * inch))
        for art_type, count in artifact_counts.items():
            story.append(Paragraph(f"• {art_type}: {count}", styles['Normal']))
    
    story.append(Spacer(1, 0.3 * inch))
    
    # Timeline Table
    if artifacts:
        story.append(Paragraph("<b>Detailed Timeline:</b>", styles['Heading2']))
        story.append(Spacer(1, 0.1 * inch))
        
        # Build table data
        table_data = [['Timestamp', 'Type', 'Name', 'Details']]
        for art in artifacts[:50]:  # Limit to first 50 for PDF size
            timestamp = art.created_at.strftime('%Y-%m-%d %H:%M')
            art_type = art.type
            name = art.name[:40] if art.name else 'N/A'
            details = f"PID: {art.pid}" if art.pid else ""
            if art.port:
                details += f" Port: {art.port}"
            
            table_data.append([timestamp, art_type, name, details])
        
        # Create table
        t = Table(table_data, colWidths=[1.5*inch, 1*inch, 2.5*inch, 1.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        story.append(t)
    
    # AI-Powered Threat Analysis Section
    story.append(Spacer(1, 0.4 * inch))
    story.append(Paragraph("<b>AI-Powered Threat Analysis:</b>", styles['Heading2']))
    
    if artifacts:
        # Call Ollama to analyze artifacts for threats
        import json
        import urllib.request
        
        # Build artifact summary for AI
        artifact_summary = []
        for art in artifacts[:10]:  # Send only first 10 to LLM for faster processing
            info = f"- [{art.type}] {art.name}"
            if art.pid:
                info += f" (PID: {art.pid})"
            artifact_summary.append(info)
        
        artifact_text = "\n".join(artifact_summary)
        
        # Construct a shorter AI prompt
        prompt = f"""You are a security analyst. Review these processes and flag any suspicious ones:

{artifact_text}

For each suspicious item, briefly state: WHY suspicious, Threat Level (Low/Medium/High), and Action needed.
If all look normal, say "No threats detected" and list what you saw."""
        
        try:
            # Call Ollama with shorter prompt
            OLLAMA_URL = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False
            }
            
            data_bytes = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(OLLAMA_URL, data=data_bytes, headers={'Content-Type': 'application/json'})

            with urllib.request.urlopen(req, timeout=500) as response:  # 2 minute timeout
                result_body = response.read().decode("utf-8")
                result_json = json.loads(result_body)
                ai_analysis = result_json.get("response", "AI analysis unavailable.")
                
                # Add AI analysis to PDF
                analysis_style = ParagraphStyle(
                    'Analysis',
                    parent=styles['Normal'],
                    fontSize=10,
                    textColor=colors.HexColor('#333333'),
                    leftIndent=20,
                    spaceAfter=10
                )
                
                # Split analysis into paragraphs for better formatting
                for paragraph in ai_analysis.split('\n\n'):
                    if paragraph.strip():
                        story.append(Paragraph(paragraph.replace('\n', '<br/>'), analysis_style))
                        story.append(Spacer(1, 0.1 * inch))
                
        except Exception as e:
            # If AI analysis fails, note it in the report
            story.append(Paragraph(
                f"<i>Note: Automated threat analysis unavailable. Ensure Ollama is running for AI-powered insights. Error: {str(e)[:100]}</i>",
                styles['Normal']
            ))
    else:
        story.append(Paragraph("No artifacts available for analysis.", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    
    # 5. Return PDF as file download
    return FileResponse(
        pdf_path,
        media_type='application/pdf',
        filename=f'Case_{case_id}_Report.pdf',
        headers={"Content-Disposition": f"attachment; filename=Case_{case_id}_Report.pdf"}
    )
