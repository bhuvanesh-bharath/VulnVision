"""
VulnVision Remediation API Blueprint.
RESTful endpoints for remediation recommendations.
"""
from flask import Blueprint, jsonify, request
from backend.models.scan import Scan
from backend.repositories.scan_repository import ScanRepository
from backend.services.remediation.remediation_engine import RemediationEngine
from backend.utils.logger import get_logger

logger = get_logger(__name__)
remediation_bp = Blueprint('remediation', __name__)


@remediation_bp.route('/', methods=['GET'])
def get_remediation():
    """Get remediation recommendations for a scan."""
    scan_id = request.args.get('scan_id', type=int)

    if not scan_id:
        repo = ScanRepository()
        recent = repo.get_recent(limit=1)
        if recent:
            scan_id = recent[0].id
        else:
            return jsonify({'recommendations': [], 'message': 'No scans available'})

    engine = RemediationEngine()
    recommendations = engine.generate(scan_id)

    return jsonify({
        'recommendations': recommendations,
        'total': len(recommendations),
        'scan_id': scan_id,
    })


@remediation_bp.route('/generate', methods=['POST'])
def generate_remediation():
    """Generate remediation recommendations for a scan."""
    data = request.get_json()
    scan_id = data.get('scan_id')

    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400

    engine = RemediationEngine()
    recommendations = engine.generate(scan_id)

    logger.info('Generated %d remediation recommendations for scan %d', len(recommendations), scan_id)
    return jsonify({
        'message': f'Generated {len(recommendations)} recommendations',
        'recommendations': recommendations,
        'total': len(recommendations),
    }), 201


@remediation_bp.route('/priorities', methods=['GET'])
def get_priorities():
    """Get prioritized remediation list."""
    scan_id = request.args.get('scan_id', type=int)

    if not scan_id:
        repo = ScanRepository()
        recent = repo.get_recent(limit=1)
        if recent:
            scan_id = recent[0].id
        else:
            return jsonify({'priorities': []})

    engine = RemediationEngine()
    recommendations = engine.generate(scan_id)
    priorities = sorted(recommendations, key=lambda r: (r['priority'], -(r.get('cvss_score') or 0)))

    return jsonify({
        'priorities': priorities[:20],
        'total': len(priorities),
    })
