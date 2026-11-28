"""
AutoSOC Day 12 Tests - LLM Foundation: Provider Contract, Config & Runtime Status
================================================================================
Covers:
  1. Validated LLM configuration defaults, bounds, URL safety, and no OpenAI vendor coupling
  2. Provider-neutral protocol compliance and strict request/response schema invariants
  3. Ollama adapter readiness and generation via mocked httpx transports (zero network calls)
  4. Timeout, unavailable server, model-not-found, HTTP 4xx/5xx, and malformed JSON handling
  5. LLMRuntimeService and GET /api/v1/llm/status across all 5 states:
     disabled, unconfigured, ready, unavailable, error
  6. Secret, credential, raw-event, prompt, and trace sanitization in errors/status output
"""

import asyncio
import json
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from main import app
from app.core.config import Settings
from app.llm import (
    DeterministicFixtureLLMProvider,
    LLMErrorCategoryEnum,
    LLMGenerationRequest,
    LLMGenerationResponse,
    LLMMessage,
    LLMProviderCapabilities,
    LLMProviderProtocol,
    LLMProviderStatusEnum,
    LLMProviderStatusResponse,
    LLMRuntimeService,
    OllamaLLMProvider,
    scrub_llm_error_message,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Configuration Validation & Disabled Baseline
# ---------------------------------------------------------------------------


def test_llm_settings_defaults_and_validation():
    s = Settings()
    assert s.LLM_ENABLED is False
    assert s.LLM_PROVIDER == "ollama"
    assert s.LLM_MODEL == ""
    assert s.LLM_BASE_URL == "http://localhost:11434"
    assert s.LLM_TIMEOUT_SECONDS == 30.0
    assert s.LLM_MAX_TOKENS == 512
    assert s.LLM_TEMPERATURE == 0.1

    # Trailing slash normalization
    s_slash = Settings(LLM_BASE_URL="http://ollama.internal:11434/")
    assert s_slash.LLM_BASE_URL == "http://ollama.internal:11434"

    # Empty base URL collapses cleanly to None (triggers unconfigured status)
    s_empty = Settings(LLM_BASE_URL="   ")
    assert s_empty.LLM_BASE_URL is None

    # Disallow paid/unsupported OpenAI vendor selection in Day 12
    with pytest.raises(ValidationError):
        Settings(LLM_PROVIDER="openai")

    # Reject non-http schemes, embedded URL credentials, queries, bad bounds
    with pytest.raises(ValidationError):
        Settings(LLM_BASE_URL="ftp://localhost:11434")
    with pytest.raises(ValidationError):
        Settings(LLM_BASE_URL="http://user:secretpass@localhost:11434")
    with pytest.raises(ValidationError):
        Settings(LLM_BASE_URL="http://localhost:11434/api?token=abc")
    with pytest.raises(ValidationError):
        Settings(LLM_TIMEOUT_SECONDS=0.0)
    with pytest.raises(ValidationError):
        Settings(LLM_TIMEOUT_SECONDS=301.0)
    with pytest.raises(ValidationError):
        Settings(LLM_MAX_TOKENS=0)
    with pytest.raises(ValidationError):
        Settings(LLM_TEMPERATURE=2.5)
    with pytest.raises(ValidationError):
        Settings(LLM_MODEL="bad\nmodel")


def test_disabled_llm_runtime_makes_zero_network_calls():
    async def _run():
        service = LLMRuntimeService(
            settings_obj=Settings(LLM_ENABLED=False, LLM_MODEL="llama3.1:8b")
        )
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=AssertionError("Should never open HTTP connection when disabled"),
        ):
            status_res = await service.get_status()
            assert status_res.enabled is False
            assert status_res.status == LLMProviderStatusEnum.DISABLED
            assert status_res.available is False

            gen_res = await service.generate(
                LLMGenerationRequest(messages=[LLMMessage(role="user", content="ping")])
            )
            assert gen_res.ok is False
            assert gen_res.error is not None
            assert gen_res.error.category == LLMErrorCategoryEnum.DISABLED

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Provider Contract & Schema Invariants
# ---------------------------------------------------------------------------


def test_provider_protocol_and_schema_invariants():
    ollama = OllamaLLMProvider(base_url="http://localhost:11434", model="llama3.1:8b")
    fixture = DeterministicFixtureLLMProvider(model="fixture-soc")
    assert isinstance(ollama, LLMProviderProtocol)
    assert isinstance(fixture, LLMProviderProtocol)
    assert ollama.capabilities.supports_chat is True
    assert ollama.is_configured() is True
    assert OllamaLLMProvider(base_url="http://localhost:11434", model="").is_configured() is False

    # Reject raw security payloads or secret fields on LLMGenerationRequest
    with pytest.raises(ValidationError):
        LLMGenerationRequest(
            messages=[LLMMessage(role="user", content="Analyze")],
            raw_event={"secret": "RawPayloadShouldFail"},  # type: ignore[call-arg]
        )

    # Response outcome invariant enforcement
    with pytest.raises(ValidationError):
        LLMGenerationResponse(provider="ollama", model="m", ok=True, content="   ")
    with pytest.raises(ValidationError):
        LLMGenerationResponse(provider="ollama", model="m", ok=False, content="bad", error=None)

    # Status availability invariant enforcement
    with pytest.raises(ValidationError):
        LLMProviderStatusResponse(
            enabled=True,
            configured=True,
            provider="ollama",
            model="m",
            status=LLMProviderStatusEnum.UNAVAILABLE,
            available=True,
            timeout_seconds=10.0,
            max_tokens=256,
            temperature=0.1,
            capabilities=LLMProviderCapabilities(),
        )


# ---------------------------------------------------------------------------
# 3. Mocked Ollama Adapter: Readiness & Generation Paths
# ---------------------------------------------------------------------------


def test_ollama_readiness_ready_model_missing_malformed_and_unavailable():
    async def _run():
        orig_async_client = httpx.AsyncClient

        # 3a. Ready (matches model without explicit :latest tag too)
        tags_ok = httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={"models": [{"name": "llama3.1:latest", "model": "llama3.1:latest"}]},
            )
            if req.url.path == "/api/tags"
            else httpx.Response(404)
        )
        p_ok = OllamaLLMProvider(base_url="http://ollama.local:11434/", model="llama3.1")
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=tags_ok, *a, **kw),
        ):
            st_ok = await p_ok.check_readiness()
        assert st_ok.status == LLMProviderStatusEnum.READY
        assert st_ok.available is True
        assert st_ok.error is None
        assert st_ok.base_url == "http://ollama.local:11434"

        # 3b. Model not found on server -> ERROR + model_not_found
        tags_other = httpx.MockTransport(
            lambda req: httpx.Response(200, json={"models": [{"name": "mistral:7b"}]})
        )
        p_missing = OllamaLLMProvider(base_url="http://ollama.local:11434", model="qwen2.5:14b")
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=tags_other, *a, **kw),
        ):
            st_missing = await p_missing.check_readiness()
        assert st_missing.status == LLMProviderStatusEnum.ERROR
        assert st_missing.available is False
        assert st_missing.error is not None
        assert st_missing.error.category == LLMErrorCategoryEnum.MODEL_NOT_FOUND

        # 3c. Malformed /api/tags JSON -> ERROR + malformed_response
        tags_bad = httpx.MockTransport(lambda req: httpx.Response(200, text="not-json"))
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=tags_bad, *a, **kw),
        ):
            st_bad = await p_ok.check_readiness()
        assert st_bad.status == LLMProviderStatusEnum.ERROR
        assert st_bad.error is not None
        assert st_bad.error.category == LLMErrorCategoryEnum.MALFORMED_RESPONSE

        # 3d. Connection refused -> UNAVAILABLE
        def _connect_err(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused", request=req)

        tags_down = httpx.MockTransport(_connect_err)
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=tags_down, *a, **kw),
        ):
            st_down = await p_ok.check_readiness()
        assert st_down.status == LLMProviderStatusEnum.UNAVAILABLE
        assert st_down.available is False
        assert st_down.error is not None
        assert st_down.error.category == LLMErrorCategoryEnum.UNAVAILABLE
        assert st_down.error.retryable is True

        # 3e. Timeout -> UNAVAILABLE + timeout category
        def _timeout_err(req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Timed out", request=req)

        tags_timeout = httpx.MockTransport(_timeout_err)
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=tags_timeout, *a, **kw),
        ):
            st_to = await p_ok.check_readiness()
        assert st_to.status == LLMProviderStatusEnum.UNAVAILABLE
        assert st_to.error is not None
        assert st_to.error.category == LLMErrorCategoryEnum.TIMEOUT
        assert st_to.error.retryable is True

    asyncio.run(_run())


def test_ollama_generate_success_and_error_modes():
    async def _run():
        orig_async_client = httpx.AsyncClient
        captured_bodies = []

        def chat_ok_handler(req: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(req.content.decode("utf-8")))
            return httpx.Response(
                200,
                json={
                    "model": "llama3.1:8b",
                    "message": {"role": "assistant", "content": '{"verdict_note":"ok"}'},
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 21,
                    "eval_count": 9,
                },
            )

        provider = OllamaLLMProvider(
            base_url="http://localhost:11434",
            model="llama3.1:8b",
            timeout_seconds=12.0,
            max_tokens=256,
            temperature=0.0,
        )
        req = LLMGenerationRequest(
            messages=[
                LLMMessage(role="system", content="Respond concisely."),
                LLMMessage(role="user", content="Summarize status"),
            ],
            json_mode=True,
        )

        # Success
        ok_transport = httpx.MockTransport(chat_ok_handler)
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=ok_transport, *a, **kw),
        ):
            res = await provider.generate(req)

        assert res.ok is True
        assert res.content == '{"verdict_note":"ok"}'
        assert res.model == "llama3.1:8b"
        assert res.finish_reason == "stop"
        assert res.usage is not None
        assert res.usage.prompt_tokens == 21
        assert res.usage.completion_tokens == 9
        assert res.usage.total_tokens == 30
        assert captured_bodies[0]["stream"] is False
        assert captured_bodies[0]["format"] == "json"
        assert captured_bodies[0]["options"] == {"temperature": 0.0, "num_predict": 256}

        # 404 Model not found
        nf_transport = httpx.MockTransport(lambda r: httpx.Response(404, json={"error": "model not found"}))
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=nf_transport, *a, **kw),
        ):
            res_404 = await provider.generate(req)
        assert res_404.ok is False
        assert res_404.error is not None
        assert res_404.error.category == LLMErrorCategoryEnum.MODEL_NOT_FOUND
        assert res_404.error.retryable is False

        # Empty/malformed message content
        mal_transport = httpx.MockTransport(
            lambda r: httpx.Response(200, json={"message": {"role": "assistant", "content": ""}})
        )
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=mal_transport, *a, **kw),
        ):
            res_mal = await provider.generate(req)
        assert res_mal.ok is False
        assert res_mal.error is not None
        assert res_mal.error.category == LLMErrorCategoryEnum.MALFORMED_RESPONSE

        # Timeout
        def _chat_timeout(r: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("read timed out", request=r)

        to_transport = httpx.MockTransport(_chat_timeout)
        with patch(
            "app.llm.ollama_adapter.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=to_transport, *a, **kw),
        ):
            res_to = await provider.generate(req)
        assert res_to.ok is False
        assert res_to.error is not None
        assert res_to.error.category == LLMErrorCategoryEnum.TIMEOUT
        assert res_to.error.retryable is True

    asyncio.run(_run())


def test_runtime_service_enforces_timeout_against_slow_provider():
    class SlowStubProvider(DeterministicFixtureLLMProvider):
        async def generate(self, request: LLMGenerationRequest) -> LLMGenerationResponse:
            await asyncio.sleep(0.25)
            return await super().generate(request)

    async def _run():
        svc = LLMRuntimeService(
            settings_obj=Settings(
                LLM_ENABLED=True,
                LLM_PROVIDER="fixture",
                LLM_MODEL="slow-model",
                LLM_TIMEOUT_SECONDS=0.05,
            ),
            provider=SlowStubProvider(model="slow-model"),
        )
        res = await svc.generate(
            LLMGenerationRequest(messages=[LLMMessage(role="user", content="hello")])
        )
        assert res.ok is False
        assert res.error is not None
        assert res.error.category == LLMErrorCategoryEnum.TIMEOUT

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. API Endpoint (/api/v1/llm/status) & Sanitization Checks
# ---------------------------------------------------------------------------


def test_llm_status_endpoint_covers_all_five_states_and_sanitizes_output():
    # 1. Default baseline -> disabled
    resp_disabled = client.get("/api/v1/llm/status")
    assert resp_disabled.status_code == 200
    body_dis = resp_disabled.json()
    assert body_dis["enabled"] is False
    assert body_dis["status"] == "disabled"
    assert body_dis["available"] is False

    # 2. Unconfigured (enabled=True, model="")
    svc_unconf = LLMRuntimeService(
        settings_obj=Settings(LLM_ENABLED=True, LLM_PROVIDER="ollama", LLM_MODEL="")
    )
    with patch("app.api.v1.endpoints.llm._default_llm_service", svc_unconf):
        resp_unconf = client.get("/api/v1/llm/status")
    assert resp_unconf.status_code == 200
    assert resp_unconf.json()["status"] == "unconfigured"
    assert resp_unconf.json()["configured"] is False
    assert resp_unconf.json()["available"] is False

    # 3. Ready (deterministic fixture provider)
    svc_ready = LLMRuntimeService(
        settings_obj=Settings(LLM_ENABLED=True, LLM_PROVIDER="fixture", LLM_MODEL="llama3.1:8b"),
        provider=DeterministicFixtureLLMProvider(
            model="llama3.1:8b",
            fixed_response="PROMPT_OR_GEN_SECRET_SHOULD_NOT_APPEAR",
        ),
    )
    with patch("app.api.v1.endpoints.llm._default_llm_service", svc_ready):
        resp_ready = client.get("/api/v1/llm/status")
    assert resp_ready.status_code == 200
    assert resp_ready.json()["status"] == "ready"
    assert resp_ready.json()["available"] is True
    assert "PROMPT_OR_GEN_SECRET_SHOULD_NOT_APPEAR" not in resp_ready.text

    # 4. Unavailable
    svc_unavail = LLMRuntimeService(
        settings_obj=Settings(LLM_ENABLED=True, LLM_PROVIDER="fixture", LLM_MODEL="llama3.1:8b"),
        provider=DeterministicFixtureLLMProvider(
            model="llama3.1:8b",
            ready=False,
            error_category=LLMErrorCategoryEnum.UNAVAILABLE,
        ),
    )
    with patch("app.api.v1.endpoints.llm._default_llm_service", svc_unavail):
        resp_unavail = client.get("/api/v1/llm/status")
    assert resp_unavail.status_code == 200
    assert resp_unavail.json()["status"] == "unavailable"
    assert resp_unavail.json()["available"] is False

    # 5. Error
    svc_err = LLMRuntimeService(
        settings_obj=Settings(LLM_ENABLED=True, LLM_PROVIDER="fixture", LLM_MODEL="llama3.1:8b"),
        provider=DeterministicFixtureLLMProvider(
            model="llama3.1:8b",
            ready=False,
            error_category=LLMErrorCategoryEnum.MODEL_NOT_FOUND,
        ),
    )
    with patch("app.api.v1.endpoints.llm._default_llm_service", svc_err):
        resp_err = client.get("/api/v1/llm/status")
    assert resp_err.status_code == 200
    assert resp_err.json()["status"] == "error"
    assert resp_err.json()["error"]["category"] == "model_not_found"


def test_error_scrubber_strips_credentials_tokens_and_traces():
    msg = (
        "Failed calling http://admin:supersecret@ollama.local:11434 "
        "Bearer sk-top-secret api_key=xyz\nTraceback (most recent call last):\n  File x"
    )
    scrubbed = scrub_llm_error_message(msg, secrets=["supersecret"])
    assert "supersecret" not in scrubbed
    assert "sk-top-secret" not in scrubbed
    assert "xyz" not in scrubbed
    assert "Traceback" not in scrubbed
    assert "\n" not in scrubbed
