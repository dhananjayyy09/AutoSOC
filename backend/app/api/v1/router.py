from fastapi import APIRouter
from app.api.v1.endpoints import system

api_v1_router = APIRouter()
api_v1_router.include_router(system.router, prefix="/system", tags=["System"])
