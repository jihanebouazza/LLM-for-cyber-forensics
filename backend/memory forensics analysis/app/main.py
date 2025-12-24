from fastapi import FastAPI, Depends
from .database import engine, Base
from .routers import memory_images, volatility, artifacts, analysis, cases, upload, chat
from . import models

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Memory Forensics API")

app.include_router(memory_images.router)
app.include_router(upload.router)
app.include_router(volatility.router)
app.include_router(artifacts.router)
app.include_router(analysis.router)
app.include_router(cases.router)
app.include_router(chat.router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the Memory Forensics LLM API"}
