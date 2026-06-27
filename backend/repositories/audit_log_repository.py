"""
VulnVision Audit Log Repository.
Data access layer for audit log records.
"""
from backend.repositories.base_repository import BaseRepository
from backend.models.audit_log import AuditLog
from backend.models.base import db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AuditLogRepository(BaseRepository):
    """Repository for AuditLog model operations."""
    model = AuditLog

    @classmethod
    def get_recent(cls, limit=50):
        """Get most recent audit log entries.

        Args:
            limit: Maximum number of records.

        Returns:
            List of AuditLog instances.
        """
        return AuditLog.query.order_by(
            AuditLog.timestamp.desc()
        ).limit(limit).all()

    @classmethod
    def get_by_entity(cls, entity_type, entity_id):
        """Get audit logs for a specific entity.

        Args:
            entity_type: Type of entity (scan, host, etc.).
            entity_id: ID of the entity.

        Returns:
            List of AuditLog instances.
        """
        return AuditLog.query.filter_by(
            entity_type=entity_type, entity_id=entity_id
        ).order_by(AuditLog.timestamp.desc()).all()

    @classmethod
    def get_by_action(cls, action, limit=50):
        """Get audit logs filtered by action type.

        Args:
            action: Action type string.
            limit: Maximum number of records.

        Returns:
            List of AuditLog instances.
        """
        return AuditLog.query.filter_by(action=action).order_by(
            AuditLog.timestamp.desc()
        ).limit(limit).all()

    @classmethod
    def create_log(cls, action, entity_type, entity_id=None, details=None,
                   ip_address=None, user_agent=None):
        """Create a new audit log entry.

        Args:
            action: Action performed.
            entity_type: Type of entity affected.
            entity_id: ID of the entity.
            details: Additional details.
            ip_address: Client IP address.
            user_agent: Client user agent.

        Returns:
            Created AuditLog instance.
        """
        entry = AuditLog(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(entry)
        db.session.commit()
        return entry
