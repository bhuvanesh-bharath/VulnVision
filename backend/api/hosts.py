"""
VulnVision Hosts API Routes.
RESTful API endpoints for querying discovered network hosts,
their ports, and associated vulnerabilities.
"""
from flask import Blueprint, jsonify, request

from backend.models.base import db
from backend.models.host import Host
from backend.models.port import Port
from backend.models.vulnerability import Vulnerability
from backend.models.scan import Scan
from backend.utils.logger import get_logger
from backend.utils.exceptions import NotFoundError

logger = get_logger(__name__)

hosts_bp = Blueprint('hosts', __name__)


@hosts_bp.route('/', methods=['GET'])
def list_hosts():
    """List all discovered hosts with optional filtering.

    Query Parameters:
        scan_id (str): Filter by scan UUID string.
        status (str): Filter by host status (up, down, unknown, filtered).

    Returns:
        JSON response with list of host objects.
    """
    scan_id_filter = request.args.get('scan_id')
    status_filter = request.args.get('status')

    query = Host.query.order_by(Host.risk_score.desc())

    if scan_id_filter:
        scan = Scan.query.filter_by(scan_id=scan_id_filter).first()
        if scan:
            query = query.filter_by(scan_id=scan.id)
        else:
            return jsonify({'hosts': [], 'total': 0}), 200

    if status_filter and status_filter in Host.VALID_STATUSES:
        query = query.filter_by(status=status_filter)

    hosts = query.all()

    return jsonify({
        'hosts': [host.to_dict() for host in hosts],
        'total': len(hosts),
    }), 200


@hosts_bp.route('/<host_id>', methods=['GET'])
def get_host(host_id):
    """Get detailed information for a specific host.

    Includes host properties, open ports, and detected vulnerabilities.

    Args:
        host_id: UUID string identifying the host.

    Returns:
        JSON response with host details, ports, and vulnerabilities.

    Raises:
        NotFoundError: If host with given host_id does not exist.
    """
    host = Host.query.filter_by(host_id=host_id).first()
    if not host:
        raise NotFoundError('Host', host_id)

    host_data = host.to_dict()
    host_data['ports'] = [p.to_dict() for p in host.ports.order_by(Port.port_number).all()]
    host_data['vulnerabilities'] = [
        v.to_dict() for v in host.vulnerabilities.order_by(Vulnerability.cvss_score.desc()).all()
    ]

    return jsonify({'host': host_data}), 200


@hosts_bp.route('/<host_id>/ports', methods=['GET'])
def get_host_ports(host_id):
    """Get all ports discovered on a specific host.

    Args:
        host_id: UUID string identifying the host.

    Returns:
        JSON response with list of port objects.

    Raises:
        NotFoundError: If host with given host_id does not exist.
    """
    host = Host.query.filter_by(host_id=host_id).first()
    if not host:
        raise NotFoundError('Host', host_id)

    ports = host.ports.order_by(Port.port_number).all()

    return jsonify({
        'host_id': host.host_id,
        'ports': [port.to_dict() for port in ports],
        'total': len(ports),
        'open_count': sum(1 for p in ports if p.state == 'open'),
    }), 200


@hosts_bp.route('/<host_id>/vulnerabilities', methods=['GET'])
def get_host_vulnerabilities(host_id):
    """Get all vulnerabilities detected on a specific host.

    Args:
        host_id: UUID string identifying the host.

    Returns:
        JSON response with list of vulnerability objects.

    Raises:
        NotFoundError: If host with given host_id does not exist.
    """
    host = Host.query.filter_by(host_id=host_id).first()
    if not host:
        raise NotFoundError('Host', host_id)

    vulns = host.vulnerabilities.order_by(Vulnerability.cvss_score.desc()).all()

    return jsonify({
        'host_id': host.host_id,
        'vulnerabilities': [v.to_dict() for v in vulns],
        'total': len(vulns),
    }), 200


@hosts_bp.route('/statistics', methods=['GET'])
def host_statistics():
    """Get aggregated host statistics across all scans.

    Returns:
        JSON response with host counts by status, OS distribution,
        and risk score metrics.
    """
    total = Host.query.count()

    by_status = {}
    for status in Host.VALID_STATUSES:
        by_status[status] = Host.query.filter_by(status=status).count()

    os_distribution = db.session.query(
        Host.os_guess, db.func.count(Host.id)
    ).group_by(Host.os_guess).all()

    os_stats = {}
    for os_name, count in os_distribution:
        label = os_name if os_name else 'Unknown'
        os_stats[label] = count

    avg_risk = db.session.query(db.func.avg(Host.risk_score)).scalar() or 0.0
    max_risk = db.session.query(db.func.max(Host.risk_score)).scalar() or 0.0

    total_open_ports = Port.query.filter_by(state='open').count()

    high_risk_hosts = Host.query.filter(Host.risk_score >= 7.0).count()

    return jsonify({
        'total_hosts': total,
        'by_status': by_status,
        'os_distribution': os_stats,
        'average_risk_score': round(float(avg_risk), 2),
        'max_risk_score': round(float(max_risk), 2),
        'high_risk_hosts': high_risk_hosts,
        'total_open_ports': total_open_ports,
    }), 200
