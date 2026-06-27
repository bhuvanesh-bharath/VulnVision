"""
VulnVision Host Model.
Represents a discovered network host with its properties and discovery metadata.
"""
import uuid
from datetime import datetime, timezone

from backend.models.base import db, TimestampMixin, SerializeMixin


class Host(db.Model, TimestampMixin, SerializeMixin):
    """Discovered network host."""
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    mac_address = db.Column(db.String(17), nullable=True)
    os_guess = db.Column(db.String(255), nullable=True)
    os_confidence = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(20), nullable=False, default='up')
    discovery_method = db.Column(db.String(50), nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)

    # Relationships
    ports = db.relationship('Port', backref='host', lazy='dynamic', cascade='all, delete-orphan')
    vulnerabilities = db.relationship('Vulnerability', backref='host', lazy='dynamic', cascade='all, delete-orphan')

    VALID_STATUSES = ('up', 'down', 'unknown', 'filtered')

    def __repr__(self):
        return f'<Host {self.ip_address} status={self.status}>'

    @property
    def open_port_count(self):
        """Count of open ports on this host."""
        return self.ports.filter_by(state='open').count()

    @property
    def vulnerability_count(self):
        """Count of vulnerabilities on this host."""
        return self.vulnerabilities.count()

    @property
    def critical_vulnerability_count(self):
        """Count of critical/high vulnerabilities."""
        return self.vulnerabilities.filter(
            Vulnerability.severity.in_(['critical', 'high'])
        ).count()

    def to_dict(self):
        """Serialize host with computed metrics."""
        data = super().to_dict()
        data['open_port_count'] = self.open_port_count
        data['vulnerability_count'] = self.vulnerability_count
        return data


# Import here to avoid circular imports in the property
from backend.models.vulnerability import Vulnerability
