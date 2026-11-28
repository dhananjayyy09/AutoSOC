"""
AutoSOC - Threat Intelligence TTL Cache & Single-Flight Guard (Day 10)

Provides:
  - Canonical cache key generation keyed by (provider, observable_type, normalized_value)
  - Bounded in-memory LRU+TTL cache with injectable clock for deterministic tests
  - Optional reuse of existing Redis service (`redis_service.client`) with seamless fallback
  - Strict validation gate refusing to cache malformed, failed, timeout, or raw-leak outputs
  - Loop-safe single-flight coalescing so concurrent requests never stampede providers
"""

import asyncio
from collections import OrderedDict
import hashlib
import json
import logging
import time
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from weakref import WeakKeyDictionary

from pydantic import ValidationError

from app.services.redis_client import redis_service
from app.threat_intelligence.schemas import (
    ObservableTypeEnum,
    ThreatIntelLookupResult,
    ThreatIntelLookupStatusEnum,
    contains_forbidden_ti_keys,
)

logger = logging.getLogger("autosoc")

_CACHE_PREFIX = "autosoc:ti:v1"
_MAX_DIRECT_VALUE_KEY_CHARS = 160


def build_ti_cache_key(
    provider: str,
    observable_type: ObservableTypeEnum,
    normalized_value: str,
) -> str:
    """
    Build a deterministic cache key explicitly bound to provider, observable type,
    and canonical normalized value. Long or special-char values use a SHA-256 digest suffix
    while retaining observable_type and provider prefixes.
    """
    clean_provider = provider.strip().lower()
    if (
        len(normalized_value) <= _MAX_DIRECT_VALUE_KEY_CHARS
        and not any(ch.isspace() for ch in normalized_value)
    ):
        value_part = normalized_value
    else:
        digest = hashlib.sha256(normalized_value.encode("utf-8")).hexdigest()
        value_part = f"sha256:{digest}"
    return f"{_CACHE_PREFIX}:{clean_provider}:{observable_type.value}:{value_part}"


class ThreatIntelCache:
    """
    Two-tier (in-process LRU+TTL + optional Redis) Threat Intelligence lookup cache
    with single-flight request coalescing.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = 300,
        max_memory_entries: int = 2048,
        use_redis: bool = True,
        redis_client_getter: Optional[Callable[[], Any]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._ttl_seconds = max(1, int(ttl_seconds))
        self._max_memory_entries = max(16, int(max_memory_entries))
        self._use_redis = bool(use_redis)
        self._redis_client_getter = redis_client_getter or (lambda: redis_service.client)
        self._clock = clock or time.monotonic

        # key -> (expires_at_monotonic, validated_payload_json)
        self._memory: "OrderedDict[str, Tuple[float, str]]" = OrderedDict()
        # Per-event-loop inflight coalescing map (safe across repeated asyncio.run calls)
        self._inflight: "WeakKeyDictionary[asyncio.AbstractEventLoop, Dict[str, asyncio.Future[ThreatIntelLookupResult]]]" = WeakKeyDictionary()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def _get_redis_client(self) -> Any:
        if not self._use_redis:
            return None
        try:
            return self._redis_client_getter()
        except Exception:
            return None

    def _evict_expired_memory(self, now: float) -> None:
        expired_keys = [k for k, (exp, _) in self._memory.items() if exp <= now]
        for key in expired_keys:
            self._memory.pop(key, None)

    @staticmethod
    def _deserialize_and_verify(
        raw_json: str,
        *,
        expected_provider: str,
        expected_type: ObservableTypeEnum,
        expected_value: str,
    ) -> Optional[ThreatIntelLookupResult]:
        try:
            data = json.loads(raw_json)
            if not isinstance(data, dict) or contains_forbidden_ti_keys(data):
                return None
            result = ThreatIntelLookupResult(**data)
        except (ValueError, TypeError, ValidationError):
            return None

        if (
            result.provider != expected_provider
            or result.observable_type != expected_type
            or result.normalized_value != expected_value
            or result.lookup_status != ThreatIntelLookupStatusEnum.SUCCESS
        ):
            return None

        return result.model_copy(
            update={
                "lookup_status": ThreatIntelLookupStatusEnum.CACHE_HIT,
                "live_lookup_performed": False,
                "cache_hit": True,
            }
        )

    async def get(
        self,
        *,
        provider: str,
        observable_type: ObservableTypeEnum,
        normalized_value: str,
    ) -> Optional[ThreatIntelLookupResult]:
        key = build_ti_cache_key(provider, observable_type, normalized_value)
        now = self._clock()
        self._evict_expired_memory(now)

        mem_entry = self._memory.get(key)
        if mem_entry is not None:
            expires_at, payload_json = mem_entry
            if expires_at > now:
                self._memory.move_to_end(key)
                verified = self._deserialize_and_verify(
                    payload_json,
                    expected_provider=provider,
                    expected_type=observable_type,
                    expected_value=normalized_value,
                )
                if verified is not None:
                    return verified
            self._memory.pop(key, None)

        redis_client = self._get_redis_client()
        if redis_client is not None:
            try:
                raw_redis = await redis_client.get(key)
                if isinstance(raw_redis, bytes):
                    raw_redis = raw_redis.decode("utf-8", errors="replace")
                if isinstance(raw_redis, str):
                    verified = self._deserialize_and_verify(
                        raw_redis,
                        expected_provider=provider,
                        expected_type=observable_type,
                        expected_value=normalized_value,
                    )
                    if verified is not None:
                        self._store_memory(key, raw_redis, now)
                        return verified
                    await redis_client.delete(key)
            except Exception as exc:
                logger.debug("TI Redis cache get skipped (%s)", type(exc).__name__)

        return None

    def _store_memory(self, key: str, payload_json: str, now: float) -> None:
        self._memory[key] = (now + self._ttl_seconds, payload_json)
        self._memory.move_to_end(key)
        while len(self._memory) > self._max_memory_entries:
            self._memory.popitem(last=False)

    async def set(self, result: ThreatIntelLookupResult) -> bool:
        """
        Persist only validated SUCCESS results without forbidden keys.
        Malformed, partial, timeout, or unavailable outcomes are never cached.
        """
        if result.lookup_status != ThreatIntelLookupStatusEnum.SUCCESS:
            return False

        try:
            validated = ThreatIntelLookupResult(
                **result.model_copy(update={"cache_hit": False}).model_dump()
            )
        except (ValidationError, ValueError, TypeError):
            return False

        payload_dict = validated.model_dump()
        if contains_forbidden_ti_keys(payload_dict):
            return False

        key = build_ti_cache_key(
            validated.provider,
            validated.observable_type,
            validated.normalized_value,
        )
        payload_json = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True)
        self._store_memory(key, payload_json, self._clock())

        redis_client = self._get_redis_client()
        if redis_client is not None:
            try:
                await redis_client.setex(key, self._ttl_seconds, payload_json)
            except Exception as exc:
                logger.debug("TI Redis cache set skipped (%s)", type(exc).__name__)
        return True

    async def get_or_fetch_singleflight(
        self,
        *,
        provider: str,
        observable_type: ObservableTypeEnum,
        normalized_value: str,
        fetcher: Callable[[], Awaitable[ThreatIntelLookupResult]],
    ) -> ThreatIntelLookupResult:
        """
        Return a valid cached result if present; otherwise coalesce concurrent calls
        for the same (provider, observable_type, normalized_value) into a single
        in-flight provider execution and cache only validated SUCCESS outcomes.
        """
        cached = await self.get(
            provider=provider,
            observable_type=observable_type,
            normalized_value=normalized_value,
        )
        if cached is not None:
            return cached

        key = build_ti_cache_key(provider, observable_type, normalized_value)
        loop = asyncio.get_running_loop()
        loop_map = self._inflight.setdefault(loop, {})

        existing_future = loop_map.get(key)
        if existing_future is not None:
            return await asyncio.shield(existing_future)

        # Double-check cache before issuing network call
        cached_after_wait = await self.get(
            provider=provider,
            observable_type=observable_type,
            normalized_value=normalized_value,
        )
        if cached_after_wait is not None:
            return cached_after_wait

        future: asyncio.Future[ThreatIntelLookupResult] = loop.create_future()
        future.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
        loop_map[key] = future
        try:
            result = await fetcher()
            if result.lookup_status == ThreatIntelLookupStatusEnum.SUCCESS:
                await self.set(result)
            if not future.done():
                future.set_result(result)
            return result
        except BaseException as exc:
            if not future.done():
                future.set_exception(exc)
            raise
        finally:
            if loop_map.get(key) is future:
                loop_map.pop(key, None)

    def clear_memory(self) -> None:
        self._memory.clear()
