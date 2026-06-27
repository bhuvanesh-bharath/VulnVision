"""
VulnVision Dashboard Routes.
Server-side rendered page routes for the main web interface.
"""
from flask import Blueprint, render_template, request

from backend.models.base import db
from backend.models.scan import Scan
from backend.models.host import Host
from backend.models.port import Port
from backend.models.vulnerability import Vulnerability
from backend.models.attack_path import AttackPath
from backend.models.security_debt import SecurityDebt
from backend.models.report import Report
from backend.utils.logger import get_logger
from backend.utils.exceptions import NotFoundError

logger = get_logger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
def index():
    """Render the main dashboard with aggregated statistics.

    Displays overall scan metrics, severity distribution, recent scans,
    and recently detected vulnerabilities.

    Returns:
        Rendered dashboard.html template with context data.
    """
    total_scans = Scan.query.count()
    total_hosts = Host.query.count()
    total_vulns = Vulnerability.query.count()
    active_vulns = Vulnerability.query.filter_by(status='open').count()
    running_scans = Scan.query.filter_by(status='running').count()

    stats = {
        'total_scans': total_scans,
        'total_hosts': total_hosts,
        'total_vulnerabilities': total_vulns,
        'active_vulnerabilities': active_vulns,
        'running_scans': running_scans,
        'completed_scans': Scan.query.filter_by(status='completed').count(),
        'hosts_up': Host.query.filter_by(status='up').count(),
    }

    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()

    severity_distribution = {
        'critical': Vulnerability.query.filter_by(severity='critical', status='open').count(),
        'high': Vulnerability.query.filter_by(severity='high', status='open').count(),
        'medium': Vulnerability.query.filter_by(severity='medium', status='open').count(),
        'low': Vulnerability.query.filter_by(severity='low', status='open').count(),
        'info': Vulnerability.query.filter_by(severity='info', status='open').count(),
    }

    recent_vulns = Vulnerability.query.order_by(
        Vulnerability.detected_at.desc()
    ).limit(10).all()

    logger.debug('Dashboard loaded: %d scans, %d hosts, %d vulns', total_scans, total_hosts, total_vulns)

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_scans=recent_scans,
        severity_distribution=severity_distribution,
        recent_vulns=recent_vulns,
    )


@dashboard_bp.route('/scans')
def scans_page():
    """Render the scans listing page.

    Supports optional query parameters for filtering.

    Returns:
        Rendered scans.html template with all scans.
    """
    status_filter = request.args.get('status')
    query = Scan.query.order_by(Scan.created_at.desc())

    if status_filter and status_filter in Scan.VALID_STATUSES:
        query = query.filter_by(status=status_filter)

    scans = query.all()

    return render_template('scans.html', scans=scans, current_status=status_filter)


@dashboard_bp.route('/scans/<scan_id>')
def scan_detail_page(scan_id):
    """Render detailed view of a specific scan.

    Args:
        scan_id: UUID string identifying the scan.

    Returns:
        Rendered scan_detail.html template with scan data.

    Raises:
        NotFoundError: If scan with given scan_id does not exist.
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        raise NotFoundError('Scan', scan_id)

    hosts = scan.hosts.order_by(Host.risk_score.desc()).all()
    vulns = scan.vulnerabilities.order_by(Vulnerability.severity).all()
    attack_paths = scan.attack_paths.order_by(AttackPath.risk_score.desc()).all()
    debt = scan.security_debts.order_by(SecurityDebt.calculated_at.desc()).first()

    severity_distribution = {
        'critical': scan.vulnerabilities.filter_by(severity='critical').count(),
        'high': scan.vulnerabilities.filter_by(severity='high').count(),
        'medium': scan.vulnerabilities.filter_by(severity='medium').count(),
        'low': scan.vulnerabilities.filter_by(severity='low').count(),
        'info': scan.vulnerabilities.filter_by(severity='info').count(),
    }

    return render_template(
        'scan_detail.html',
        scan=scan,
        hosts=hosts,
        vulnerabilities=vulns,
        attack_paths=attack_paths,
        security_debt=debt,
        severity_distribution=severity_distribution,
    )


@dashboard_bp.route('/hosts')
def hosts_page():
    """Render the hosts listing page.

    Returns:
        Rendered hosts.html template with all discovered hosts.
    """
    hosts = Host.query.order_by(Host.risk_score.desc()).all()
    return render_template('hosts.html', hosts=hosts)


@dashboard_bp.route('/hosts/<host_id>')
def host_detail_page(host_id):
    """Render detailed view of a specific host.

    Args:
        host_id: UUID string identifying the host.

    Returns:
        Rendered host_detail.html template with host data.

    Raises:
        NotFoundError: If host with given host_id does not exist.
    """
    host = Host.query.filter_by(host_id=host_id).first()
    if not host:
        raise NotFoundError('Host', host_id)

    ports = host.ports.order_by(Port.port_number).all()
    vulns = host.vulnerabilities.order_by(Vulnerability.severity).all()

    return render_template(
        'host_detail.html',
        host=host,
        ports=ports,
        vulnerabilities=vulns,
    )


@dashboard_bp.route('/vulnerabilities')
def vulnerabilities_page():
    """Render the vulnerabilities listing page with filters.

    Supports query parameters: severity, category, status.

    Returns:
        Rendered vulnerabilities.html template with filtered vulnerabilities.
    """
    severity_filter = request.args.get('severity')
    category_filter = request.args.get('category')
    status_filter = request.args.get('status')

    query = Vulnerability.query.order_by(Vulnerability.detected_at.desc())

    if severity_filter and severity_filter in Vulnerability.VALID_SEVERITIES:
        query = query.filter_by(severity=severity_filter)
    if category_filter and category_filter in Vulnerability.CATEGORIES:
        query = query.filter_by(category=category_filter)
    if status_filter and status_filter in Vulnerability.VALID_STATUSES:
        query = query.filter_by(status=status_filter)

    vulnerabilities = query.all()

    return render_template(
        'vulnerabilities.html',
        vulnerabilities=vulnerabilities,
        severities=Vulnerability.VALID_SEVERITIES,
        categories=Vulnerability.CATEGORIES,
        statuses=Vulnerability.VALID_STATUSES,
        current_severity=severity_filter,
        current_category=category_filter,
        current_status=status_filter,
    )


@dashboard_bp.route('/attack-paths')
def attack_paths_page():
    """Render the attack paths listing page.

    Returns:
        Rendered attack_paths.html template with all attack paths.
    """
    attack_paths = AttackPath.query.order_by(AttackPath.risk_score.desc()).all()
    return render_template('attack_paths.html', attack_paths=attack_paths)


@dashboard_bp.route('/security-debt')
def security_debt_page():
    """Render the security debt history page.

    Returns:
        Rendered security_debt.html template with debt history.
    """
    debt_history = SecurityDebt.query.order_by(SecurityDebt.calculated_at.desc()).all()
    latest_debt = debt_history[0] if debt_history else None

    return render_template(
        'security_debt.html',
        debt_history=debt_history,
        latest_debt=latest_debt,
    )


@dashboard_bp.route('/reports')
def reports_page():
    """Render the reports listing page.

    Returns:
        Rendered reports.html template with all generated reports.
    """
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('reports.html', reports=reports)


@dashboard_bp.route('/remediation')
def remediation_page():
    """Render the remediation recommendations page.

    Returns:
        Rendered remediation.html template with prioritized remediation data.
    """
    latest_scan = Scan.query.filter_by(status='completed').order_by(
        Scan.created_at.desc()
    ).first()

    recommendations = []
    if latest_scan:
        try:
            from backend.services.remediation.remediation_engine import RemediationEngine
            engine = RemediationEngine()
            recommendations = engine.generate(latest_scan.id)
        except Exception as e:
            logger.error('Failed to generate remediation: %s', str(e))

    return render_template(
        'remediation.html',
        recommendations=recommendations,
    )


def _calculate_priority(vuln):
    """Calculate remediation priority score for a vulnerability.

    Higher scores indicate higher priority for remediation. The score
    combines severity weight and CVSS score with confidence.

    Args:
        vuln: Vulnerability model instance.

    Returns:
        Float priority score (0-100).
    """
    severity_weights = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.5,
    }
    base_weight = severity_weights.get(vuln.severity, 1.0)
    cvss_factor = vuln.cvss_score / 10.0 if vuln.cvss_score else 0.0
    confidence_factor = vuln.confidence if vuln.confidence else 0.5

    return round((base_weight * 5 + cvss_factor * 30 + confidence_factor * 20), 2)
