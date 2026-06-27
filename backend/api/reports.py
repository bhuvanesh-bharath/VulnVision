"""
VulnVision Reports API Blueprint.
RESTful endpoints for report generation and management.
"""
import os
from flask import Blueprint, jsonify, request, send_file
from backend.repositories.report_repository import ReportRepository
from backend.models.base import db
from backend.models.report import Report
from backend.models.scan import Scan
from backend.services.reporting.report_generator import ReportGenerator
from backend.utils.logger import get_logger

logger = get_logger(__name__)
reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/', methods=['GET'])
def list_reports():
    """List all reports."""
    repo = ReportRepository()
    reports = repo.get_recent(limit=50)
    return jsonify({
        'reports': [r.to_dict() for r in reports],
        'total': len(reports),
    })


@reports_bp.route('/', methods=['POST'])
def generate_report():
    """Generate a new report."""
    data = request.get_json()
    scan_id = data.get('scan_id')
    name = data.get('name', 'Security Report')
    report_type = data.get('report_type', 'full')
    fmt = data.get('format', 'json')

    if not scan_id:
        return jsonify({'error': 'scan_id is required'}), 400

    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    valid_formats = {'pdf', 'csv', 'json'}
    if fmt not in valid_formats:
        return jsonify({'error': f'Invalid format. Must be one of: {valid_formats}'}), 400

    report = Report(
        scan_id=scan_id,
        name=name,
        report_type=report_type,
        format=fmt,
        include_findings=data.get('include_findings', True),
        include_attack_paths=data.get('include_attack_paths', True),
        include_remediation=data.get('include_remediation', True),
        include_executive_summary=data.get('include_executive_summary', True),
        status='pending',
    )
    db.session.add(report)
    db.session.commit()

    try:
        generator = ReportGenerator()
        file_path = generator.generate(report.id)
        logger.info('Report %s generated: %s', report.report_id, file_path)
    except Exception as e:
        logger.error('Report generation failed: %s', str(e))
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

    return jsonify({
        'message': 'Report generated successfully',
        'report': report.to_dict(),
    }), 201


@reports_bp.route('/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get report details."""
    repo = ReportRepository()
    report = repo.get_by_report_id(report_id)
    return jsonify({'report': report.to_dict()})


@reports_bp.route('/<report_id>/download', methods=['GET'])
def download_report(report_id):
    """Download a generated report file."""
    repo = ReportRepository()
    report = repo.get_by_report_id(report_id)

    if not report.file_path or not os.path.exists(report.file_path):
        return jsonify({'error': 'Report file not found'}), 404

    return send_file(
        report.file_path,
        as_attachment=True,
        download_name=os.path.basename(report.file_path)
    )


@reports_bp.route('/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    """Delete a report and its file."""
    repo = ReportRepository()
    report = repo.get_by_report_id(report_id)

    if report.file_path and os.path.exists(report.file_path):
        os.remove(report.file_path)

    db.session.delete(report)
    db.session.commit()

    logger.info('Report %s deleted', report_id)
    return jsonify({'message': 'Report deleted'})
