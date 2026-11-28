from fastapi import APIRouter
from app.api.v1.endpoints import events, llm, system

api_v1_router = APIRouter()
api_v1_router.include_router(system.router, prefix="/system", tags=["System"])
api_v1_router.include_router(events.router, prefix="/events", tags=["Events"])
api_v1_router.include_router(llm.router, prefix="/llm", tags=["LLM"])
