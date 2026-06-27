"""
VulnVision Report Repository.
Data access layer for report records.
"""
from backend.repositories.base_repository import BaseRepository
from backend.models.report import Report
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ReportRepository(BaseRepository):
    """Repository for Report model operations."""
    model = Report

    @classmethod
    def get_by_report_id(cls, report_id):
        """Get report by UUID report_id.

        Args:
            report_id: UUID string identifier.

        Returns:
            Report instance.

        Raises:
            NotFoundError: If not found.
        """
        report = Report.query.filter_by(report_id=report_id).first()
        if not report:
            from backend.utils.exceptions import NotFoundError
            raise NotFoundError('Report', report_id)
        return report

    @classmethod
    def get_by_scan(cls, scan_id):
        """Get all reports for a scan.

        Args:
            scan_id: Scan primary key ID.

        Returns:
            List of Report instances.
        """
        return Report.query.filter_by(scan_id=scan_id).order_by(
            Report.created_at.desc()
        ).all()

    @classmethod
    def get_recent(cls, limit=10):
        """Get most recent reports.

        Args:
            limit: Maximum number of records.

        Returns:
            List of Report instances.
        """
        return Report.query.order_by(
            Report.created_at.desc()
        ).limit(limit).all()

    @classmethod
    def get_by_format(cls, fmt):
        """Get reports filtered by format.

        Args:
            fmt: Report format (pdf, csv, json).

        Returns:
            List of Report instances.
        """
        return Report.query.filter_by(format=fmt).order_by(
            Report.created_at.desc()
        ).all()
