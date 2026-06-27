"""
VulnVision Port Model.
Represents a discovered port on a network host with service information.
"""
from backend.models.base import db, TimestampMixin, SerializeMixin


class Port(db.Model, TimestampMixin, SerializeMixin):
    """Discovered port and service on a host."""
    __tablename__ = 'ports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default='tcp')
    state = db.Column(db.String(20), nullable=False, default='open')
    service_name = db.Column(db.String(100), nullable=True)
    service_version = db.Column(db.String(255), nullable=True)
    banner = db.Column(db.Text, nullable=True)
    tunnel = db.Column(db.String(50), nullable=True)
    confidence = db.Column(db.Integer, nullable=True, default=0)

    __table_args__ = (
        db.UniqueConstraint('host_id', 'port_number', 'protocol', name='uq_host_port_proto'),
    )

    VALID_STATES = ('open', 'closed', 'filtered', 'open|filtered')
    VALID_PROTOCOLS = ('tcp', 'udp', 'sctp')

    def __repr__(self):
        return f'<Port {self.port_number}/{self.protocol} state={self.state} service={self.service_name}>'

    @property
    def is_open(self):
        """Check if port is open."""
        return self.state == 'open'

    @property
    def display_name(self):
        """Human-readable port description."""
        name = f'{self.port_number}/{self.protocol}'
        if self.service_name:
            name += f' ({self.service_name})'
        return name

    def to_dict(self):
        """Serialize port with display name."""
        data = super().to_dict()
        data['display_name'] = self.display_name
        data['is_open'] = self.is_open
        return data
