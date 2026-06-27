"""
VulnVision Port Repository.
Data access layer for Port model with port and service query operations.
"""
from sqlalchemy import func

from backend.models.base import db
from backend.models.port import Port
from backend.models.host import Host
from backend.repositories.base_repository import BaseRepository
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class PortRepository(BaseRepository):
    """Repository for Port model database operations.

    Provides methods for querying ports by host, state, service,
    port number, and computing port statistics across scans.
    """

    model = Port

    @classmethod
    def get_by_host(cls, host_id):
        """Get all ports for a specific host.

        Args:
            host_id: Primary key ID of the host.

        Returns:
            List of Port instances ordered by port number.
        """
        return Port.query.filter_by(host_id=host_id).order_by(Port.port_number).all()

    @classmethod
    def get_open_ports(cls, host_id):
        """Get all open ports for a specific host.

        Args:
            host_id: Primary key ID of the host.

        Returns:
            List of Port instances where state is 'open', ordered by port number.
        """
        return Port.query.filter_by(
            host_id=host_id, state='open'
        ).order_by(Port.port_number).all()

    @classmethod
    def get_by_service(cls, service_name, scan_id=None):
        """Get all ports running a specific service.

        Args:
            service_name: Name of the service to search for (case-insensitive).
            scan_id: Optional scan primary key to scope the search.

        Returns:
            List of Port instances matching the service name.
        """
        query = Port.query.filter(
            func.lower(Port.service_name) == func.lower(service_name)
        )
        if scan_id is not None:
            query = query.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )
        return query.order_by(Port.port_number).all()

    @classmethod
    def get_port_statistics(cls, scan_id=None):
        """Get aggregate port statistics, optionally scoped to a scan.

        Args:
            scan_id: Optional scan primary key to scope statistics.

        Returns:
            Dictionary containing:
                - total_ports: total number of port records
                - open_ports: count of ports with state='open'
                - closed_ports: count of ports with state='closed'
                - filtered_ports: count of ports with state='filtered'
                - common_ports: list of dicts with port_number and count, top 20
                - service_counts: dict mapping service_name to count
                - protocol_counts: dict mapping protocol to count
        """
        base_query = Port.query
        if scan_id is not None:
            base_query = base_query.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )

        total_ports = base_query.count()

        open_count_q = Port.query.filter_by(state='open')
        closed_count_q = Port.query.filter_by(state='closed')
        filtered_count_q = Port.query.filter_by(state='filtered')
        if scan_id is not None:
            open_count_q = open_count_q.join(Host, Port.host_id == Host.id).filter(Host.scan_id == scan_id)
            closed_count_q = closed_count_q.join(Host, Port.host_id == Host.id).filter(Host.scan_id == scan_id)
            filtered_count_q = filtered_count_q.join(Host, Port.host_id == Host.id).filter(Host.scan_id == scan_id)

        open_ports = open_count_q.count()
        closed_ports = closed_count_q.count()
        filtered_ports = filtered_count_q.count()

        common_q = db.session.query(
            Port.port_number,
            func.count(Port.id).label('cnt')
        )
        if scan_id is not None:
            common_q = common_q.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )
        common_q = common_q.filter(Port.state == 'open').group_by(
            Port.port_number
        ).order_by(func.count(Port.id).desc()).limit(20)
        common_ports = [
            {'port_number': row[0], 'count': row[1]}
            for row in common_q.all()
        ]

        service_q = db.session.query(
            func.coalesce(Port.service_name, 'unknown'),
            func.count(Port.id)
        )
        if scan_id is not None:
            service_q = service_q.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )
        service_q = service_q.filter(Port.state == 'open').group_by(
            func.coalesce(Port.service_name, 'unknown')
        ).all()
        service_counts = {name: count for name, count in service_q}

        protocol_q = db.session.query(
            Port.protocol,
            func.count(Port.id)
        )
        if scan_id is not None:
            protocol_q = protocol_q.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )
        protocol_q = protocol_q.group_by(Port.protocol).all()
        protocol_counts = {proto: count for proto, count in protocol_q}

        return {
            'total_ports': total_ports,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'filtered_ports': filtered_ports,
            'common_ports': common_ports,
            'service_counts': service_counts,
            'protocol_counts': protocol_counts,
        }

    @classmethod
    def get_by_port_number(cls, port_number, scan_id=None):
        """Get all port records for a specific port number.

        Args:
            port_number: The port number to search for.
            scan_id: Optional scan primary key to scope the search.

        Returns:
            List of Port instances matching the port number.
        """
        query = Port.query.filter_by(port_number=port_number)
        if scan_id is not None:
            query = query.join(Host, Port.host_id == Host.id).filter(
                Host.scan_id == scan_id
            )
        return query.order_by(Port.host_id).all()
