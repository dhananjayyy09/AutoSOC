from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()

@router.get("/info", summary="System Information")
async def get_system_info():
    """
    Returns basic platform metadata, version, and API tier.
    """
    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "api_version": "v1",
        "environment": settings.APP_ENV
    }
