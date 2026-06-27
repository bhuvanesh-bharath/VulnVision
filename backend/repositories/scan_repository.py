"""
VulnVision Scan Repository.
Data access layer for Scan model with query methods for scan lifecycle management.
"""
from datetime import datetime, timezone

from sqlalchemy import func, case

from backend.models.base import db
from backend.models.scan import Scan
from backend.repositories.base_repository import BaseRepository
from backend.utils.logger import get_logger
from backend.utils.exceptions import NotFoundError, DatabaseError

logger = get_logger(__name__)


class ScanRepository(BaseRepository):
    """Repository for Scan model database operations.

    Provides methods beyond base CRUD for scan-specific queries
    including status filtering, progress tracking, and statistics.
    """

    model = Scan

    @classmethod
    def get_by_scan_id(cls, scan_id):
        """Look up a scan by its UUID scan_id field.

        Args:
            scan_id: UUID string identifying the scan.

        Returns:
            Scan instance.

        Raises:
            NotFoundError: If no scan matches the given scan_id.
        """
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        if not scan:
            raise NotFoundError('Scan', scan_id)
        return scan

    @classmethod
    def get_recent(cls, limit=10):
        """Get the most recent scans ordered by creation time.

        Args:
            limit: Maximum number of scans to return. Defaults to 10.

        Returns:
            List of Scan instances ordered by created_at descending.
        """
        return Scan.query.order_by(Scan.created_at.desc()).limit(limit).all()

    @classmethod
    def get_by_status(cls, status):
        """Get all scans with a specific status.

        Args:
            status: Scan status string (pending, running, completed, failed, cancelled).

        Returns:
            List of Scan instances matching the status.
        """
        return Scan.query.filter_by(status=status).order_by(Scan.created_at.desc()).all()

    @classmethod
    def get_running(cls):
        """Get all currently running scans.

        Returns:
            List of Scan instances with status='running'.
        """
        return Scan.query.filter_by(status='running').order_by(Scan.start_time.desc()).all()

    @classmethod
    def update_progress(cls, scan_id, progress, hosts_discovered, vulnerabilities_found):
        """Update scan progress counters.

        Args:
            scan_id: Primary key ID of the scan to update.
            progress: Current progress percentage (0-100).
            hosts_discovered: Number of hosts discovered so far.
            vulnerabilities_found: Number of vulnerabilities found so far.

        Raises:
            NotFoundError: If the scan does not exist.
            DatabaseError: If the update fails.
        """
        try:
            scan = cls.get_by_id(scan_id)
            scan.progress = min(max(progress, 0), 100)
            scan.hosts_discovered = hosts_discovered
            scan.vulnerabilities_found = vulnerabilities_found
            db.session.commit()
            logger.debug(
                'Updated scan %d progress: %d%%, hosts=%d, vulns=%d',
                scan_id, progress, hosts_discovered, vulnerabilities_found
            )
        except NotFoundError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to update scan progress for id=%d: %s', scan_id, str(e))
            raise DatabaseError(f'Failed to update scan progress: {str(e)}')

    @classmethod
    def get_scan_statistics(cls):
        """Get aggregate scan statistics across all scans.

        Returns:
            Dictionary containing:
                - status_counts: dict mapping each status to its count
                - total_scans: total number of scans
                - total_hosts_discovered: sum of hosts discovered
                - total_vulnerabilities_found: sum of vulnerabilities found
                - avg_progress: average progress of all scans
                - avg_duration_seconds: average duration of completed scans
                - completed_count: number of completed scans
                - failed_count: number of failed scans
                - running_count: number of running scans
        """
        total_scans = Scan.query.count()

        status_rows = db.session.query(
            Scan.status,
            func.count(Scan.id)
        ).group_by(Scan.status).all()
        status_counts = {status: count for status, count in status_rows}

        aggregates = db.session.query(
            func.coalesce(func.sum(Scan.hosts_discovered), 0),
            func.coalesce(func.sum(Scan.vulnerabilities_found), 0),
            func.coalesce(func.avg(Scan.progress), 0)
        ).first()

        total_hosts_discovered = int(aggregates[0])
        total_vulnerabilities_found = int(aggregates[1])
        avg_progress = round(float(aggregates[2]), 1)

        completed_scans = Scan.query.filter(
            Scan.status == 'completed',
            Scan.start_time.isnot(None),
            Scan.end_time.isnot(None)
        ).all()

        if completed_scans:
            durations = [
                (s.end_time - s.start_time).total_seconds()
                for s in completed_scans
            ]
            avg_duration = round(sum(durations) / len(durations), 1)
        else:
            avg_duration = 0.0

        return {
            'status_counts': status_counts,
            'total_scans': total_scans,
            'total_hosts_discovered': total_hosts_discovered,
            'total_vulnerabilities_found': total_vulnerabilities_found,
            'avg_progress': avg_progress,
            'avg_duration_seconds': avg_duration,
            'completed_count': status_counts.get('completed', 0),
            'failed_count': status_counts.get('failed', 0),
            'running_count': status_counts.get('running', 0),
        }
