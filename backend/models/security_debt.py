"""
VulnVision Security Debt Model.
Tracks accumulated security debt over time, measuring vulnerability exposure trends.
"""
import uuid
from datetime import datetime, timezone

from backend.models.base import db, TimestampMixin, SerializeMixin


class SecurityDebt(db.Model, TimestampMixin, SerializeMixin):
    """Security debt assessment for a scan."""
    __tablename__ = 'security_debts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    debt_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    debt_score = db.Column(db.Float, nullable=False, default=0.0)
    vulnerability_debt = db.Column(db.Float, nullable=False, default=0.0)
    legacy_service_debt = db.Column(db.Float, nullable=False, default=0.0)
    exposure_debt = db.Column(db.Float, nullable=False, default=0.0)
    configuration_debt = db.Column(db.Float, nullable=False, default=0.0)
    trend = db.Column(db.String(20), nullable=False, default='stable')
    trend_percentage = db.Column(db.Float, nullable=False, default=0.0)
    details = db.Column(db.JSON, nullable=True)
    recommendations = db.Column(db.JSON, nullable=True)
    calculated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    VALID_TRENDS = ('improving', 'stable', 'degrading')

    DEBT_THRESHOLDS = {
        'critical': 80.0,
        'high': 60.0,
        'medium': 40.0,
        'low': 20.0,
        'minimal': 0.0
    }

    def __repr__(self):
        return f'<SecurityDebt {self.debt_id} score={self.debt_score} trend={self.trend}>'

    @property
    def debt_rating(self):
        """Calculate overall debt rating from score.

        Returns:
            String rating: critical, high, medium, low, or minimal.
        """
        for rating, threshold in self.DEBT_THRESHOLDS.items():
            if self.debt_score >= threshold:
                return rating
        return 'minimal'

    @property
    def debt_breakdown(self):
        """Get breakdown of debt components.

        Returns:
            Dictionary of debt component scores.
        """
        total = max(self.debt_score, 0.01)
        return {
            'vulnerability': {
                'score': self.vulnerability_debt,
                'percentage': round((self.vulnerability_debt / total) * 100, 1)
            },
            'legacy_service': {
                'score': self.legacy_service_debt,
                'percentage': round((self.legacy_service_debt / total) * 100, 1)
            },
            'exposure': {
                'score': self.exposure_debt,
                'percentage': round((self.exposure_debt / total) * 100, 1)
            },
            'configuration': {
                'score': self.configuration_debt,
                'percentage': round((self.configuration_debt / total) * 100, 1)
            }
        }

    def to_dict(self):
        """Serialize security debt with computed fields."""
        data = super().to_dict()
        data['debt_rating'] = self.debt_rating
        data['debt_breakdown'] = self.debt_breakdown
        return data
