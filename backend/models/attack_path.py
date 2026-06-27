"""
VulnVision Attack Path Model.
Represents a simulated attack chain through discovered network vulnerabilities.
"""
import uuid
from datetime import datetime, timezone

from backend.models.base import db, TimestampMixin, SerializeMixin


class AttackPath(db.Model, TimestampMixin, SerializeMixin):
    """Simulated attack path through the network."""
    __tablename__ = 'attack_paths'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    path_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    chain = db.Column(db.JSON, nullable=False, default=list)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    likelihood = db.Column(db.Float, nullable=False, default=0.0)
    impact = db.Column(db.Float, nullable=False, default=0.0)
    entry_point = db.Column(db.String(255), nullable=True)
    target_asset = db.Column(db.String(255), nullable=True)
    path_length = db.Column(db.Integer, nullable=False, default=0)
    attack_complexity = db.Column(db.String(20), nullable=False, default='medium')
    requires_authentication = db.Column(db.Boolean, nullable=False, default=False)

    COMPLEXITY_LEVELS = ('low', 'medium', 'high')

    def __repr__(self):
        return f'<AttackPath {self.path_id} risk={self.risk_score} steps={self.path_length}>'

    @property
    def composite_score(self):
        """Calculate composite attack path score.

        Returns:
            Weighted score combining likelihood and impact.
        """
        return round((self.likelihood * 0.4 + self.impact * 0.6) * 10, 2)

    @property
    def chain_summary(self):
        """Generate a human-readable summary of the attack chain.

        Returns:
            String describing the attack progression.
        """
        if not self.chain:
            return 'No steps defined'

        steps = []
        for i, step in enumerate(self.chain, 1):
            host = step.get('host', 'unknown')
            action = step.get('action', 'access')
            service = step.get('service', '')
            step_desc = f'Step {i}: {action} on {host}'
            if service:
                step_desc += f' via {service}'
            steps.append(step_desc)
        return ' → '.join(steps)

    def to_dict(self):
        """Serialize attack path with computed fields."""
        data = super().to_dict()
        data['composite_score'] = self.composite_score
        data['chain_summary'] = self.chain_summary
        return data
