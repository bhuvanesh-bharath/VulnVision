"""
VulnVision Attack Path Repository.
Data access layer for attack path records.
"""
from backend.repositories.base_repository import BaseRepository
from backend.models.attack_path import AttackPath
from backend.models.base import db
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AttackPathRepository(BaseRepository):
    """Repository for AttackPath model operations."""
    model = AttackPath

    @classmethod
    def get_by_path_id(cls, path_id):
        """Get attack path by UUID path_id.

        Args:
            path_id: UUID string identifier.

        Returns:
            AttackPath instance.

        Raises:
            NotFoundError: If not found.
        """
        path = AttackPath.query.filter_by(path_id=path_id).first()
        if not path:
            from backend.utils.exceptions import NotFoundError
            raise NotFoundError('AttackPath', path_id)
        return path

    @classmethod
    def get_by_scan(cls, scan_id):
        """Get all attack paths for a scan ordered by risk score descending.

        Args:
            scan_id: Scan primary key ID.

        Returns:
            List of AttackPath instances.
        """
        return AttackPath.query.filter_by(scan_id=scan_id).order_by(
            AttackPath.risk_score.desc()
        ).all()

    @classmethod
    def get_high_risk(cls, min_score=7.0):
        """Get attack paths above a risk threshold.

        Args:
            min_score: Minimum risk score.

        Returns:
            List of AttackPath instances.
        """
        return AttackPath.query.filter(
            AttackPath.risk_score >= min_score
        ).order_by(AttackPath.risk_score.desc()).all()

    @classmethod
    def get_attack_path_statistics(cls, scan_id=None):
        """Get aggregate statistics for attack paths.

        Args:
            scan_id: Optional scan ID to filter by.

        Returns:
            Dictionary of statistics.
        """
        query = AttackPath.query
        if scan_id:
            query = query.filter_by(scan_id=scan_id)

        paths = query.all()
        total = len(paths)

        if total == 0:
            return {
                'total': 0,
                'avg_risk_score': 0,
                'max_risk_score': 0,
                'high_risk_count': 0,
                'avg_path_length': 0,
                'complexity_distribution': {'low': 0, 'medium': 0, 'high': 0}
            }

        risk_scores = [p.risk_score for p in paths]
        complexity_dist = {'low': 0, 'medium': 0, 'high': 0}
        for p in paths:
            c = p.attack_complexity if p.attack_complexity in complexity_dist else 'medium'
            complexity_dist[c] += 1

        return {
            'total': total,
            'avg_risk_score': round(sum(risk_scores) / total, 2),
            'max_risk_score': round(max(risk_scores), 2),
            'high_risk_count': sum(1 for s in risk_scores if s >= 7.0),
            'avg_path_length': round(sum(p.path_length for p in paths) / total, 1),
            'complexity_distribution': complexity_dist
        }
