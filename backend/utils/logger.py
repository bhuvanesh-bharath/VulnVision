"""
VulnVision Logging System.
Configures application, scan, error, and audit logging with rotation.
"""
import os
import logging
import logging.handlers
from datetime import datetime, timezone

from backend.config import Config


_loggers_initialized = False


def setup_logging():
    """Configure the complete logging system for VulnVision."""
    global _loggers_initialized
    if _loggers_initialized:
        return
    _loggers_initialized = True

    os.makedirs(Config.LOG_DIR, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    if root_logger.handlers:
        root_logger.handlers.clear()

    formatter = logging.Formatter(
        fmt=Config.LOG_FORMAT,
        datefmt=Config.LOG_DATE_FORMAT
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, Config.LOG_LEVEL, logging.INFO))
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    _setup_file_logger('vulnvision', 'application.log', formatter, Config.LOG_LEVEL)
    _setup_file_logger('vulnvision.scanner', 'scanner.log', formatter, 'DEBUG')
    _setup_file_logger('vulnvision.error', 'error.log', formatter, 'ERROR')
    _setup_file_logger('vulnvision.audit', 'audit.log', formatter, 'INFO')


def _setup_file_logger(logger_name, filename, formatter, level):
    """Configure a rotating file handler for a specific logger.

    Args:
        logger_name: Name of the logger to configure.
        filename: Log file name.
        formatter: Log formatter instance.
        level: Logging level string.
    """
    log_path = os.path.join(Config.LOG_DIR, filename)
    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8'
    )
    handler.setLevel(getattr(logging, level, logging.INFO))
    handler.setFormatter(formatter)

    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger.propagate = True


def get_logger(name):
    """Get a logger instance for the given module.

    Args:
        name: Module name, typically __name__.

    Returns:
        Configured logger instance.
    """
    return logging.getLogger(f'vulnvision.{name}')


def get_scan_logger():
    """Get the scanner-specific logger.

    Returns:
        Scanner logger instance.
    """
    return logging.getLogger('vulnvision.scanner')


def get_audit_logger():
    """Get the audit logger for tracking user actions.

    Returns:
        Audit logger instance.
    """
    return logging.getLogger('vulnvision.audit')


def log_audit_event(action, entity_type, entity_id, details=None, ip_address=None):
    """Log an audit event.

    Args:
        action: Action performed (create, update, delete, etc.).
        entity_type: Type of entity affected.
        entity_id: ID of the entity.
        details: Additional details about the action.
        ip_address: IP address of the requester.
    """
    audit_logger = get_audit_logger()
    timestamp = datetime.now(timezone.utc).isoformat()
    message = (
        f'AUDIT | {timestamp} | action={action} | '
        f'entity_type={entity_type} | entity_id={entity_id} | '
        f'ip={ip_address or "unknown"}'
    )
    if details:
        message += f' | details={details}'
    audit_logger.info(message)
