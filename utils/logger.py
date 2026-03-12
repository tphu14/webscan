"""
logger.py - Structured logging với structlog.
Output: human-readable trong terminal, JSON khi dùng --log-file.
"""
import logging
import sys
import structlog


_configured = False


def setup_logger(level: str = "INFO", log_file: str | None = None) -> structlog.BoundLogger:
    global _configured
    if _configured:
        return structlog.get_logger()

    log_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=handlers,
    )

    # Chọn renderer theo context
    if log_file:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.BoundLogger,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _configured = True
    return structlog.get_logger()


def get_logger(name: str = "webscan") -> structlog.BoundLogger:
    return structlog.get_logger(name)