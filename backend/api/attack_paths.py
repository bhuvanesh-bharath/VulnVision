"""
VulnVision Attack Paths API Blueprint.
RESTful endpoints for attack path management.
"""
from flask import Blueprint, jsonify, request
from backend.repositories.attack_path_repository import AttackPathRepository
from backend.services.attack_path.attack_path_engine import AttackPathEngine
from backend.utils.logger import get_logger

logger = get_logger(__name__)
attack_paths_bp = Blueprint('attack_paths', __name__)


@attack_paths_bp.route('/', methods=['GET'])
def list_attack_paths():
    """List attack paths with optional filters."""
    scan_id = request.args.get('scan_id', type=int)
    min_score = request.args.get('min_score', type=float)

    repo = AttackPathRepository()
    if min_score:
        paths = repo.get_high_risk(min_score=min_score)
    elif scan_id:
        paths = repo.get_by_scan(scan_id)
    else:
        paths = repo.get_all()

    return jsonify({
        'attack_paths': [p.to_dict() for p in paths],
        'total': len(paths),
    })


@attack_paths_bp.route('/<path_id>', methods=['GET'])
def get_attack_path(path_id):
    """Get attack path details by UUID."""
    repo = AttackPathRepository()
    path = repo.get_by_path_id(path_id)
    return jsonify({'attack_path': path.to_dict()})


@attack_paths_bp.route('/generate', methods=['POST'])
def generate_attack_paths():
    """Generate attack paths for a scan."""
    data = request.get_json()
    scan_id = data.get('scan_id')

    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400

    engine = AttackPathEngine()
    paths = engine.generate(scan_id)

    logger.info('Generated %d attack paths for scan %d', len(paths), scan_id)
    return jsonify({
        'message': f'Generated {len(paths)} attack paths',
        'attack_paths': [p.to_dict() for p in paths],
        'total': len(paths),
    }), 201


@attack_paths_bp.route('/statistics', methods=['GET'])
def attack_path_statistics():
    """Get attack path statistics."""
    scan_id = request.args.get('scan_id', type=int)
    repo = AttackPathRepository()
    stats = repo.get_attack_path_statistics(scan_id=scan_id)
    return jsonify({'statistics': stats})
