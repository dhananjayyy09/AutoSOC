"""
AutoSOC API v1 - LLM Provider Status Endpoint (Day 12)

Exposes a sanitized operational readiness snapshot for the configured local
LLM provider (`GET /api/v1/llm/status`) without sending prompts or leaking secrets.
"""

from fastapi import APIRouter, status

from app.llm import LLMProviderStatusResponse, LLMRuntimeService

router = APIRouter()
_default_llm_service = LLMRuntimeService()


@router.get(
    "/status",
    status_code=status.HTTP_200_OK,
    response_model=LLMProviderStatusResponse,
    summary="Get Configured LLM Provider Operational Status",
)
async def get_llm_provider_status() -> LLMProviderStatusResponse:
    """
    Return sanitized readiness and configuration state (disabled, unconfigured,
    ready, unavailable, or error) for the configured LLM provider.
    """
    return await _default_llm_service.get_status()
