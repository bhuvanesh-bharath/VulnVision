"""
VulnVision Scan Model.
Represents a network scan operation with its configuration and results.
"""
import uuid
from datetime import datetime, timezone

from backend.models.base import db, TimestampMixin, SerializeMixin


class Scan(db.Model, TimestampMixin, SerializeMixin):
    """Network scan record."""
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    target = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False, default='quick')
    status = db.Column(db.String(50), nullable=False, default='pending')
    progress = db.Column(db.Integer, nullable=False, default=0)
    hosts_discovered = db.Column(db.Integer, nullable=False, default=0)
    vulnerabilities_found = db.Column(db.Integer, nullable=False, default=0)
    ports_scanned = db.Column(db.Integer, nullable=False, default=0)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    configuration = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    hosts = db.relationship('Host', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    attack_paths = db.relationship('AttackPath', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    security_debts = db.relationship('SecurityDebt', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy='dynamic', cascade='all, delete-orphan')

    # Valid status transitions
    VALID_STATUSES = ('pending', 'running', 'completed', 'failed', 'cancelled')
    VALID_TYPES = ('quick', 'full', 'custom', 'targeted')

    def __repr__(self):
        return f'<Scan {self.scan_id} target={self.target} status={self.status}>'

    def start(self):
        """Mark scan as started."""
        self.status = 'running'
        self.start_time = datetime.now(timezone.utc)
        self.progress = 0

    def complete(self):
        """Mark scan as completed."""
        self.status = 'completed'
        self.end_time = datetime.now(timezone.utc)
        self.progress = 100

    def fail(self, error_message=None):
        """Mark scan as failed.

        Args:
            error_message: Description of the failure.
        """
        self.status = 'failed'
        self.end_time = datetime.now(timezone.utc)
        self.error_message = error_message

    def cancel(self):
        """Mark scan as cancelled."""
        self.status = 'cancelled'
        self.end_time = datetime.now(timezone.utc)

    @property
    def duration_seconds(self):
        """Calculate scan duration in seconds.

        Returns:
            Duration in seconds, or None if scan hasn't completed.
        """
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        if self.start_time:
            now = datetime.now(timezone.utc)
            start = self.start_time
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            return (now - start).total_seconds()
        return None

    def to_dict(self):
        """Serialize scan to dictionary with computed fields."""
        data = super().to_dict()
        data['duration_seconds'] = self.duration_seconds
        data['host_count'] = self.hosts.count() if self.hosts else 0
        data['vulnerability_count'] = self.vulnerabilities.count() if self.vulnerabilities else 0
        return data
