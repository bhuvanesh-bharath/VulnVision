"""
VulnVision Audit Log Model.
Records all significant actions for security auditing and compliance.
"""
from datetime import datetime, timezone

from backend.models.base import db, SerializeMixin


class AuditLog(db.Model, SerializeMixin):
    """Audit log entry for tracking user and system actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(100), nullable=False)
    entity_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Common action types
    ACTIONS = {
        'SCAN_CREATED': 'scan_created',
        'SCAN_STARTED': 'scan_started',
        'SCAN_COMPLETED': 'scan_completed',
        'SCAN_FAILED': 'scan_failed',
        'SCAN_CANCELLED': 'scan_cancelled',
        'VULN_DETECTED': 'vulnerability_detected',
        'VULN_RESOLVED': 'vulnerability_resolved',
        'VULN_ACCEPTED': 'vulnerability_accepted',
        'REPORT_GENERATED': 'report_generated',
        'REPORT_DOWNLOADED': 'report_downloaded',
        'HOST_DISCOVERED': 'host_discovered',
        'ATTACK_PATH_GENERATED': 'attack_path_generated',
        'DEBT_CALCULATED': 'debt_calculated',
    }

    def __repr__(self):
        return f'<AuditLog {self.action} entity={self.entity_type}:{self.entity_id}>'

    @classmethod
    def log(cls, action, entity_type, entity_id=None, details=None, ip_address=None, user_agent=None):
        """Create and persist an audit log entry.

        Args:
            action: The action being recorded.
            entity_type: Type of entity affected.
            entity_id: ID of the affected entity.
            details: Additional context about the action.
            ip_address: Client IP address.
            user_agent: Client user agent string.

        Returns:
            Created AuditLog instance.
        """
        entry = cls(
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
