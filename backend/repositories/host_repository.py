"""
VulnVision Host Repository.
Data access layer for Host model with network host query operations.
"""
from sqlalchemy import func

from backend.models.base import db
from backend.models.host import Host
from backend.models.vulnerability import Vulnerability
from backend.repositories.base_repository import BaseRepository
from backend.utils.logger import get_logger
from backend.utils.exceptions import NotFoundError, DatabaseError

logger = get_logger(__name__)


class HostRepository(BaseRepository):
    """Repository for Host model database operations.

    Provides methods for host discovery results, IP-based lookups,
    vulnerability correlation, and host statistics aggregation.
    """

    model = Host

    @classmethod
    def get_by_host_id(cls, host_id):
        """Look up a host by its UUID host_id field.

        Args:
            host_id: UUID string identifying the host.

        Returns:
            Host instance.

        Raises:
            NotFoundError: If no host matches the given host_id.
        """
        host = Host.query.filter_by(host_id=host_id).first()
        if not host:
            raise NotFoundError('Host', host_id)
        return host

    @classmethod
    def get_by_scan(cls, scan_id):
        """Get all hosts discovered in a specific scan.

        Args:
            scan_id: Primary key ID of the scan.

        Returns:
            List of Host instances belonging to the scan.
        """
        return Host.query.filter_by(scan_id=scan_id).order_by(Host.ip_address).all()

    @classmethod
    def get_by_ip(cls, ip_address):
        """Get all host records with a specific IP address.

        An IP address may appear across multiple scans, so this
        returns all matching records.

        Args:
            ip_address: IP address string to search for.

        Returns:
            List of Host instances with the given IP address.
        """
        return Host.query.filter_by(ip_address=ip_address).order_by(Host.last_seen.desc()).all()

    @classmethod
    def get_with_vulnerabilities(cls, scan_id):
        """Get hosts that have at least one vulnerability in a scan.

        Args:
            scan_id: Primary key ID of the scan.

        Returns:
            List of Host instances that have associated vulnerabilities.
        """
        return Host.query.filter_by(scan_id=scan_id).filter(
            Host.vulnerabilities.any()
        ).order_by(Host.risk_score.desc()).all()

    @classmethod
    def get_host_statistics(cls, scan_id=None):
        """Get aggregate host statistics, optionally scoped to a scan.

        Args:
            scan_id: Optional scan primary key to scope statistics. If None,
                     statistics span all scans.

        Returns:
            Dictionary containing:
                - total_hosts: total number of hosts
                - os_distribution: dict mapping os_guess to count
                - status_counts: dict mapping status to count
                - avg_risk_score: average risk score across hosts
                - hosts_with_vulns: count of hosts having vulnerabilities
        """
        query = Host.query
        if scan_id is not None:
            query = query.filter_by(scan_id=scan_id)

        total_hosts = query.count()

        os_rows = db.session.query(
            func.coalesce(Host.os_guess, 'Unknown'),
            func.count(Host.id)
        )
        if scan_id is not None:
            os_rows = os_rows.filter(Host.scan_id == scan_id)
        os_rows = os_rows.group_by(func.coalesce(Host.os_guess, 'Unknown')).all()
        os_distribution = {os_name: count for os_name, count in os_rows}

        status_rows = db.session.query(
            Host.status,
            func.count(Host.id)
        )
        if scan_id is not None:
            status_rows = status_rows.filter(Host.scan_id == scan_id)
        status_rows = status_rows.group_by(Host.status).all()
        status_counts = {status: count for status, count in status_rows}

        avg_risk_q = db.session.query(func.coalesce(func.avg(Host.risk_score), 0.0))
        if scan_id is not None:
            avg_risk_q = avg_risk_q.filter(Host.scan_id == scan_id)
        avg_risk_score = round(float(avg_risk_q.scalar()), 2)

        vuln_host_q = Host.query.filter(Host.vulnerabilities.any())
        if scan_id is not None:
            vuln_host_q = vuln_host_q.filter_by(scan_id=scan_id)
        hosts_with_vulns = vuln_host_q.count()

        return {
            'total_hosts': total_hosts,
            'os_distribution': os_distribution,
            'status_counts': status_counts,
            'avg_risk_score': avg_risk_score,
            'hosts_with_vulns': hosts_with_vulns,
        }

    @classmethod
    def update_risk_score(cls, host_id, risk_score):
        """Update the risk score for a specific host.

        Args:
            host_id: Primary key ID of the host.
            risk_score: New risk score value (0.0-10.0).

        Raises:
            NotFoundError: If the host does not exist.
            DatabaseError: If the update fails.
        """
        try:
            host = cls.get_by_id(host_id)
            host.risk_score = max(0.0, min(float(risk_score), 10.0))
            db.session.commit()
            logger.debug('Updated host %d risk_score to %.2f', host_id, host.risk_score)
        except NotFoundError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to update risk score for host id=%d: %s', host_id, str(e))
            raise DatabaseError(f'Failed to update host risk score: {str(e)}')
