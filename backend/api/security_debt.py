"""
VulnVision Security Debt API Blueprint.
RESTful endpoints for security debt tracking.
"""
from flask import Blueprint, jsonify, request
from backend.repositories.security_debt_repository import SecurityDebtRepository
from backend.services.security_debt.debt_engine import SecurityDebtEngine
from backend.utils.logger import get_logger

logger = get_logger(__name__)
security_debt_bp = Blueprint('security_debt', __name__)


@security_debt_bp.route('/', methods=['GET'])
def get_latest_debt():
    """Get the latest security debt record."""
    repo = SecurityDebtRepository()
    debt = repo.get_latest()
    if not debt:
        return jsonify({'security_debt': None, 'message': 'No security debt data available'})
    return jsonify({'security_debt': debt.to_dict()})


@security_debt_bp.route('/history', methods=['GET'])
def get_debt_history():
    """Get security debt history."""
    limit = request.args.get('limit', 30, type=int)
    repo = SecurityDebtRepository()
    records = repo.get_debt_history(limit=limit)
    return jsonify({
        'history': [r.to_dict() for r in records],
        'total': len(records),
    })


@security_debt_bp.route('/trend', methods=['GET'])
def get_debt_trend():
    """Get security debt trend data for charting."""
    repo = SecurityDebtRepository()
    trend = repo.get_debt_trend()
    return jsonify({'trend': trend})


@security_debt_bp.route('/calculate', methods=['POST'])
def calculate_debt():
    """Calculate security debt for a scan."""
    data = request.get_json()
    scan_id = data.get('scan_id')

    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400

    engine = SecurityDebtEngine()
    debt = engine.calculate(scan_id)

    logger.info('Security debt calculated for scan %d: score=%.2f', scan_id, debt.debt_score)
    return jsonify({
        'message': 'Security debt calculated',
        'security_debt': debt.to_dict(),
    }), 201
