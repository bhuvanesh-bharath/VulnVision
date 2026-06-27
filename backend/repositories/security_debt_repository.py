"""
VulnVision Security Debt Repository.
Data access layer for security debt records.
"""
from backend.repositories.base_repository import BaseRepository
from backend.models.security_debt import SecurityDebt
from backend.models.base import db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityDebtRepository(BaseRepository):
    """Repository for SecurityDebt model operations."""
    model = SecurityDebt

    @classmethod
    def get_by_scan(cls, scan_id):
        """Get security debt record for a specific scan.

        Args:
            scan_id: Scan primary key ID.

        Returns:
            SecurityDebt instance or None.
        """
        return SecurityDebt.query.filter_by(scan_id=scan_id).first()

    @classmethod
    def get_debt_history(cls, limit=30):
        """Get historical debt records ordered by date.

        Args:
            limit: Maximum number of records.

        Returns:
            List of SecurityDebt instances.
        """
        return SecurityDebt.query.order_by(
            SecurityDebt.calculated_at.desc()
        ).limit(limit).all()

    @classmethod
    def get_debt_trend(cls):
        """Get debt trend data for charting.

        Returns:
            Dictionary with labels and data points.
        """
        records = SecurityDebt.query.order_by(
            SecurityDebt.calculated_at.asc()
        ).limit(60).all()

        return {
            'labels': [r.calculated_at.strftime('%Y-%m-%d %H:%M') for r in records],
            'scores': [r.debt_score for r in records],
            'vulnerability_debt': [r.vulnerability_debt for r in records],
            'legacy_service_debt': [r.legacy_service_debt for r in records],
            'exposure_debt': [r.exposure_debt for r in records],
            'configuration_debt': [r.configuration_debt for r in records],
        }

    @classmethod
    def get_latest(cls):
        """Get the most recent security debt record.

        Returns:
            SecurityDebt instance or None.
        """
        return SecurityDebt.query.order_by(
            SecurityDebt.calculated_at.desc()
        ).first()
