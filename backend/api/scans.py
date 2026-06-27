"""
VulnVision Scans API Routes.
RESTful API endpoints for managing network scans including creation,
status tracking, and background execution via ThreadPoolExecutor.
"""
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, current_app

from backend.models.base import db
from backend.models.scan import Scan
from backend.models.host import Host
from backend.models.vulnerability import Vulnerability
from backend.models.audit_log import AuditLog
from backend.utils.logger import get_logger, log_audit_event
from backend.utils.exceptions import ValidationError, NotFoundError

logger = get_logger(__name__)

scans_bp = Blueprint('scans', __name__)

scan_executor = ThreadPoolExecutor(max_workers=3)


def run_scan_task(app, scan_id, target, scan_type, config):
    """Execute a network scan in a background thread with Flask app context.

    This function is submitted to the ThreadPoolExecutor and runs the full
    scan pipeline: host discovery, port scanning, vulnerability detection.

    Args:
        app: Flask application instance for context binding.
        scan_id: Primary key ID of the Scan record.
        target: Target IP, hostname, or CIDR range.
        scan_type: Type of scan (quick, full, custom, targeted).
        config: Optional JSON configuration dict for scan parameters.
    """
    with app.app_context():
        try:
            from backend.services.scanner.network_scanner import NetworkScanner
            scanner = NetworkScanner()
            scanner.execute_scan(scan_id, target, scan_type, config)
        except Exception as e:
            logger.error('Background scan task failed for scan_id=%s: %s', scan_id, str(e))
            try:
                scan = db.session.get(Scan, scan_id)
                if scan and scan.status == 'running':
                    scan.fail(str(e))
                    db.session.commit()
            except Exception as db_err:
                logger.error('Failed to update scan status after error: %s', str(db_err))


@scans_bp.route('/', methods=['GET'])
def list_scans():
    """List all scans with optional filtering and pagination.

    Query Parameters:
        status (str): Filter by scan status (pending, running, completed, failed, cancelled).
        limit (int): Maximum number of results (alias for per_page).
        page (int): Page number for pagination (1-indexed, default 1).
        per_page (int): Results per page (default 20, max 100).

    Returns:
        JSON response with list of scan objects and pagination metadata.
    """
    status_filter = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', request.args.get('limit', 20, type=int), type=int)
    per_page = min(per_page, 100)

    query = Scan.query.order_by(Scan.created_at.desc())

    if status_filter and status_filter in Scan.VALID_STATUSES:
        query = query.filter_by(status=status_filter)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'scans': [scan.to_dict() for scan in pagination.items],
        'pagination': {
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
        }
    }), 200


@scans_bp.route('/', methods=['POST'])
def create_scan():
    """Create a new scan and launch it in a background thread.

    Request Body (JSON):
        name (str): Human-readable scan name (required).
        target (str): Target IP, hostname, or CIDR range (required).
        scan_type (str): Scan type - quick, full, custom, targeted (default: quick).
        configuration (dict): Optional scan configuration parameters.

    Returns:
        JSON response with the created scan object and 201 status.

    Raises:
        ValidationError: If required fields are missing or scan_type is invalid.
    """
    data = request.get_json()
    if not data:
        raise ValidationError('Request body must be JSON')

    name = data.get('name')
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    configuration = data.get('configuration')

    if not name or not name.strip():
        raise ValidationError('Scan name is required')
    if not target or not target.strip():
        raise ValidationError('Scan target is required')
    if scan_type not in Scan.VALID_TYPES:
        raise ValidationError(
            f'Invalid scan type: {scan_type}. Must be one of: {", ".join(Scan.VALID_TYPES)}'
        )

    scan = Scan(
        scan_id=str(uuid.uuid4()),
        name=name.strip(),
        target=target.strip(),
        scan_type=scan_type,
        status='pending',
        configuration=configuration,
    )
    db.session.add(scan)
    db.session.commit()

    AuditLog.log(
        action=AuditLog.ACTIONS['SCAN_CREATED'],
        entity_type='Scan',
        entity_id=scan.scan_id,
        details=f'Created scan "{scan.name}" targeting {scan.target}',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
    )

    log_audit_event('scan_created', 'Scan', scan.scan_id, ip_address=request.remote_addr)

    app = current_app._get_current_object()
    scan_executor.submit(run_scan_task, app, scan.id, scan.target, scan.scan_type, scan.configuration)

    logger.info('Scan created and queued: scan_id=%s target=%s type=%s', scan.scan_id, scan.target, scan.scan_type)

    return jsonify({
        'message': 'Scan created and started',
        'scan': scan.to_dict(),
    }), 201


@scans_bp.route('/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get detailed information for a specific scan.

    Args:
        scan_id: UUID string identifying the scan.

    Returns:
        JSON response with scan details.

    Raises:
        NotFoundError: If scan with given scan_id does not exist.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        raise NotFoundError('Scan', scan_id)

    scan_data = scan.to_dict()
    scan_data['severity_distribution'] = {
        'critical': scan.vulnerabilities.filter_by(severity='critical').count(),
        'high': scan.vulnerabilities.filter_by(severity='high').count(),
        'medium': scan.vulnerabilities.filter_by(severity='medium').count(),
        'low': scan.vulnerabilities.filter_by(severity='low').count(),
        'info': scan.vulnerabilities.filter_by(severity='info').count(),
    }

    return jsonify({'scan': scan_data}), 200


@scans_bp.route('/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Cancel a running scan or delete a completed scan.

    If the scan is currently running, it will be marked as cancelled.
    Otherwise, the scan and all associated data will be deleted.

    Args:
        scan_id: UUID string identifying the scan.

    Returns:
        JSON response confirming deletion/cancellation.

    Raises:
        NotFoundError: If scan with given scan_id does not exist.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        raise NotFoundError('Scan', scan_id)

    if scan.status == 'running':
        scan.cancel()
        db.session.commit()
        AuditLog.log(
            action=AuditLog.ACTIONS['SCAN_CANCELLED'],
            entity_type='Scan',
            entity_id=scan.scan_id,
            details=f'Cancelled running scan "{scan.name}"',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
        )
        logger.info('Scan cancelled: scan_id=%s', scan.scan_id)
        return jsonify({'message': 'Scan cancelled', 'scan_id': scan.scan_id}), 200

    scan_id_str = scan.scan_id
    db.session.delete(scan)
    db.session.commit()

    logger.info('Scan deleted: scan_id=%s', scan_id_str)
    return jsonify({'message': 'Scan deleted', 'scan_id': scan_id_str}), 200


@scans_bp.route('/<scan_id>/hosts', methods=['GET'])
def get_scan_hosts(scan_id):
    """Get all hosts discovered by a specific scan.

    Args:
        scan_id: UUID string identifying the scan.

    Returns:
        JSON response with list of host objects.

    Raises:
        NotFoundError: If scan with given scan_id does not exist.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        raise NotFoundError('Scan', scan_id)

    hosts = scan.hosts.order_by(Host.risk_score.desc()).all()

    return jsonify({
        'scan_id': scan.scan_id,
        'hosts': [host.to_dict() for host in hosts],
        'total': len(hosts),
    }), 200


@scans_bp.route('/<scan_id>/vulnerabilities', methods=['GET'])
def get_scan_vulnerabilities(scan_id):
    """Get all vulnerabilities found by a specific scan.

    Args:
        scan_id: UUID string identifying the scan.

    Returns:
        JSON response with list of vulnerability objects.

    Raises:
        NotFoundError: If scan with given scan_id does not exist.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        raise NotFoundError('Scan', scan_id)

    vulns = scan.vulnerabilities.order_by(Vulnerability.cvss_score.desc()).all()

    return jsonify({
        'scan_id': scan.scan_id,
        'vulnerabilities': [v.to_dict() for v in vulns],
        'total': len(vulns),
    }), 200


@scans_bp.route('/statistics', methods=['GET'])
def scan_statistics():
    """Get overall scan statistics.

    Returns:
        JSON response with aggregated scan metrics including counts by status,
        total hosts discovered, and total vulnerabilities found.
    """
    total = Scan.query.count()
    by_status = {}
    for status in Scan.VALID_STATUSES:
        by_status[status] = Scan.query.filter_by(status=status).count()

    total_hosts = db.session.query(db.func.sum(Scan.hosts_discovered)).scalar() or 0
    total_vulns = db.session.query(db.func.sum(Scan.vulnerabilities_found)).scalar() or 0
    total_ports = db.session.query(db.func.sum(Scan.ports_scanned)).scalar() or 0

    by_type = {}
    for scan_type in Scan.VALID_TYPES:
        by_type[scan_type] = Scan.query.filter_by(scan_type=scan_type).count()

    latest_scan = Scan.query.order_by(Scan.created_at.desc()).first()

    return jsonify({
        'total_scans': total,
        'by_status': by_status,
        'by_type': by_type,
        'total_hosts_discovered': int(total_hosts),
        'total_vulnerabilities_found': int(total_vulns),
        'total_ports_scanned': int(total_ports),
        'latest_scan': latest_scan.to_dict() if latest_scan else None,
    }), 200
