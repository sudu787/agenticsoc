"""
SecureFlow AI - FastAPI Main Application
Entry point for the backend API server.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.database import init_db
from app.api import auth, dashboard, alerts, incidents, tickets, chat, demo, agents, events
from app.api import ingestion as ingestion_api
from app.api import notifications as notifications_api
from app.api import knowledge_graph as knowledge_graph_api
from app.api import security_testing as security_testing_api
from app.api import rag as rag_api
from app.api import autonomous as autonomous_api
from app.api import risk as risk_api
from app.api import compliance as compliance_api
from app.api import prediction as prediction_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("secureflow")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and start background services on startup."""
    # Initialize DB (create tables)
    init_db()

    # Pre-load knowledge base
    try:
        from app.knowledge.rag_engine import get_rag_engine
        engine = get_rag_engine()
        logger.info("✅ RAG engine loaded")
    except Exception as e:
        logger.warning(f"RAG engine failed to load: {e}")

    # Initialize knowledge graph
    try:
        from app.knowledge.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph()
        logger.info(f"✅ Knowledge graph initialized (available: {kg.available})")
    except Exception as e:
        logger.warning(f"Knowledge base failed to load: {e}")

    # Start ingestion pipeline if enabled
    ingestion_service = None
    if settings.ENABLE_INGESTION:
        try:
            from app.ingestion.ingestion_service import get_ingestion_service
            ingestion_service = get_ingestion_service()
            ingestion_service.start()
            logger.info("✅ Ingestion pipeline started")
        except Exception as e:
            logger.warning(f"Ingestion service failed to start: {e}")

    yield

    # Shutdown
    if ingestion_service:
        ingestion_service.stop()


app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(events.router, prefix="/api/events", tags=["Events"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(tickets.router, prefix="/api/tickets", tags=["Tickets"])
app.include_router(chat.router, prefix="/api/chat", tags=["Chat"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(demo.router, prefix="/api/demo", tags=["Demo"])
app.include_router(ingestion_api.router, prefix="/api/ingestion", tags=["Ingestion"])
app.include_router(notifications_api.router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(knowledge_graph_api.router, prefix="/api/knowledge-graph", tags=["Knowledge Graph"])
app.include_router(security_testing_api.router, prefix="/api/security", tags=["Security Testing"])
app.include_router(rag_api.router, prefix="/api/rag", tags=["RAG Engine"])
app.include_router(autonomous_api.router, prefix="/api/autonomous", tags=["Autonomous Response"])
app.include_router(risk_api.router, prefix="/api/risk", tags=["Risk Scoring"])
app.include_router(compliance_api.router, prefix="/api/compliance", tags=["Compliance"])
app.include_router(prediction_api.router, prefix="/api/prediction", tags=["Threat Prediction"])


@app.get("/api/health")
async def health_check():
    """Health check with component status."""
    from app.knowledge.knowledge_base import get_knowledge_base
    from app.ingestion.ingestion_service import get_ingestion_service
    from app.knowledge.knowledge_graph import get_knowledge_graph

    kb = get_knowledge_base()
    ingestion = get_ingestion_service()
    kg = get_knowledge_graph()

    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "components": {
            "knowledge_base": {
                "status": "loaded" if kb._loaded else "not_loaded",
                "documents": len(kb._documents),
            },
            "ingestion": {
                "status": "running" if ingestion._running else "stopped",
                "events_ingested": ingestion._stats.get("events_ingested", 0),
            },
            "security": {
                "prompt_injection": "active",
                "output_validation": "active",
                "canary_tokens": "active",
                "policy_engine": "active",
            },
            "knowledge_graph": kg.get_graph_stats(),
        },
    }
