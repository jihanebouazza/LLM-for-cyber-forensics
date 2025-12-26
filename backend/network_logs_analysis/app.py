from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("🚀 Démarrage de l'application Forensics LLM Analysis")
    print("=" * 60)

    # Test connexion base de données
    db_status = "❌"
    try:
        from .database import get_connection

        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        cur.close()
        conn.close()
        db_status = "✅"
        print(f"{db_status} Base de données PostgreSQL connectée")
        print(f"   Version: {version.split(',')[0]}")
    except Exception as e:
        print(f"{db_status} Erreur de connexion à la base de données")
        print(f"   Erreur: {e}")

    # Test Ollama
    ollama_status = "❌"
    try:
        import requests

        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            ollama_status = "✅"
            models = response.json().get("models", [])
            print(f"{ollama_status} Ollama accessible")
            if models:
                model_names = [m.get("name", "unknown") for m in models]
                print(f"   Modèles disponibles: {', '.join(model_names)}")
            else:
                print("   ⚠️  Aucun modèle trouvé.")
        else:
            print(f"{ollama_status} Ollama réponse inattendue: {response.status_code}")
    except Exception as e:
        print(f"{ollama_status} Ollama non accessible ou erreur: {e}")

    print("=" * 60)
    print("✅ Application démarrée avec succès!")
    print("=" * 60)
    yield
    print("\n" + "=" * 60)
    print("👋 Arrêt de l'application Forensics LLM Analysis")
    print("=" * 60)


app = FastAPI(
    title="Forensics LLM Analysis API",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Initialisation des routers
try:
    # Import du module network_log_api
    from . import network_log_api
    
    # Vérifier ce qui est disponible
    if hasattr(network_log_api, 'router'):
        app.include_router(network_log_api.router)
        logger.info("✅ API Network initialisée (via router)")
    elif hasattr(network_log_api, 'api'):
        app.include_router(network_log_api.api.router)
        logger.info("✅ API Network initialisée (via api.router)")
    elif hasattr(network_log_api, 'NetworkAPI'):
        network_api = network_log_api.NetworkAPI()
        app.include_router(network_api.router)
        logger.info("✅ API Network initialisée (via NetworkAPI)")
    else:
        logger.error("❌ Aucun router trouvé dans network_log_api")
    
    # Import et initialisation de l'API Logs (si elle existe)
    try:
        from .logs_api import LogsAPI
        logs_api = LogsAPI()
        app.include_router(logs_api.router)
        logger.info("✅ API Logs initialisée")
    except ImportError:
        logger.warning("⚠️  logs_api non trouvé - ignoré")
    
    logger.info("✅ APIs (routers) initialisées avec succès")
except Exception as e:
    logger.error(f"❌ Erreur lors de l'initialisation des APIs: {e}")
    import traceback
    traceback.print_exc()
    raise


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url),
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback

    error_id = datetime.now().strftime("%Y%m%d%H%M%S")
    logger.error(f"[{error_id}] Erreur non gérée: {exc}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "error_id": error_id,
            "path": str(request.url),
            "message": "Une erreur inattendue s'est produite. Consultez les logs du serveur.",
        },
    )


if __name__ == "__main__":
    uvicorn.run(
        "backend.network_logs_analysis.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True,
    )