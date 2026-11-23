import logging
import sys


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Configure application-wide structured logging.

    Format: timestamp | level | logger name | message
    Log level is sourced from settings.LOG_LEVEL (default INFO).
    Noisy third-party loggers are suppressed to WARNING in non-debug scenarios.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    # Only add our handler if it isn't already installed (avoids duplicate
    # output on hot-reload and preserves pytest's caplog handler in tests).
    if not any(isinstance(h, logging.StreamHandler) and h.stream is sys.stdout for h in root_logger.handlers):
        root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Suppress noisy third-party loggers unless debug level is explicitly requested
    if level > logging.DEBUG:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)

    app_logger = logging.getLogger("autosoc")
    app_logger.info("Logging configured at level: %s", log_level.upper())
    return app_logger


# Module-level logger; setup_logging() called by create_app() with the
# settings value so the level is applied before the first request arrives.
logger = logging.getLogger("autosoc")
