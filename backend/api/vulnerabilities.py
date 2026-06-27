"""
VulnVision Vulnerabilities API Blueprint.
RESTful endpoints for vulnerability management.
"""
from flask import Blueprint, jsonify, request
from backend.repositories.vulnerability_repository import VulnerabilityRepository
from backend.models.base import db
from backend.utils.logger import get_logger

logger = get_logger(__name__)
vulnerabilities_bp = Blueprint('vulnerabilities', __name__)


@vulnerabilities_bp.route('/', methods=['GET'])
def list_vulnerabilities():
    """List vulnerabilities with optional filters."""
    severity = request.args.get('severity')
    category = request.args.get('category')
    status = request.args.get('status')
    scan_id = request.args.get('scan_id', type=int)

    repo = VulnerabilityRepository()
    if severity:
        vulns = repo.get_by_severity(severity, scan_id=scan_id)
    elif category:
        vulns = repo.get_by_category(category, scan_id=scan_id)
    elif scan_id:
        vulns = repo.get_by_scan(scan_id)
    elif status == 'open':
        vulns = repo.get_active()
    else:
        vulns = repo.get_all()

    return jsonify({
        'vulnerabilities': [v.to_dict() for v in vulns],
        'total': len(vulns),
    })


@vulnerabilities_bp.route('/<vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Get vulnerability details by UUID."""
    repo = VulnerabilityRepository()
    vuln = repo.get_by_vuln_id(vuln_id)
    return jsonify({'vulnerability': vuln.to_dict()})


@vulnerabilities_bp.route('/<vuln_id>/status', methods=['PATCH'])
def update_vulnerability_status(vuln_id):
    """Update vulnerability status."""
    data = request.get_json()
    new_status = data.get('status')

    valid_statuses = {'open', 'resolved', 'accepted', 'false_positive'}
    if new_status not in valid_statuses:
        return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400

    repo = VulnerabilityRepository()
    vuln = repo.get_by_vuln_id(vuln_id)
    vuln.status = new_status
    db.session.commit()

    logger.info('Vulnerability %s status updated to %s', vuln_id, new_status)
    return jsonify({'vulnerability': vuln.to_dict()})


@vulnerabilities_bp.route('/statistics', methods=['GET'])
def vulnerability_statistics():
    """Get vulnerability statistics."""
    scan_id = request.args.get('scan_id', type=int)
    repo = VulnerabilityRepository()
    stats = repo.get_vulnerability_statistics(scan_id=scan_id)
    return jsonify({'statistics': stats})


@vulnerabilities_bp.route('/severity-distribution', methods=['GET'])
def severity_distribution():
    """Get vulnerability severity distribution."""
    scan_id = request.args.get('scan_id', type=int)
    repo = VulnerabilityRepository()
    stats = repo.get_vulnerability_statistics(scan_id=scan_id)
    return jsonify({'distribution': stats.get('severity_distribution', {})})
