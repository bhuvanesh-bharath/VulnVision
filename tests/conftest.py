"""
VulnVision Test Configuration and Shared Fixtures.
Provides reusable pytest fixtures for database sessions, sample models,
and Flask test clients used across all test modules.
"""
import pytest
from datetime import datetime, timezone

from backend.app import create_app
from backend.config import TestingConfig
from backend.models.base import db as _db
from backend.models import (
    Scan, Host, Port, Vulnerability, AttackPath, SecurityDebt, Report
)


@pytest.fixture(scope='session')
def app():
    """Create a Flask application configured for testing.

    Yields:
        Flask application instance with TestingConfig applied.
    """
    application = create_app(config_class=TestingConfig)
    yield application


@pytest.fixture(scope='function')
def client(app):
    """Create a Flask test client with a clean database.

    Args:
        app: The Flask application fixture.

    Yields:
        Flask test client instance with initialized database tables.
    """
    with app.app_context():
        _db.create_all()
        with app.test_client() as test_client:
            yield test_client
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope='function')
def db_session(app):
    """Provide a clean database session for each test function.

    Creates all tables before each test and drops them afterward to ensure
    complete isolation between tests. Uses an in-memory SQLite database
    as configured by TestingConfig.

    Args:
        app: The Flask application fixture.

    Yields:
        SQLAlchemy database instance with fresh tables.
    """
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.rollback()
        _db.drop_all()


@pytest.fixture(scope='function')
def sample_scan(db_session):
    """Create and persist a sample Scan record.

    Provides a fully populated Scan with realistic field values for
    use as a test dependency in fixtures and tests that require
    a parent scan entity.

    Args:
        db_session: The database session fixture.

    Returns:
        Persisted Scan instance.
    """
    scan = Scan(
        name='Test Network Scan',
        target='192.168.1.0/24',
        scan_type='quick',
        status='completed',
        progress=100,
        hosts_discovered=5,
        vulnerabilities_found=12,
        ports_scanned=1000,
        start_time=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 1, 15, 10, 5, 30, tzinfo=timezone.utc),
        configuration={'ports': '1-1024', 'timeout': 5}
    )
    db_session.session.add(scan)
    db_session.session.commit()
    return scan


@pytest.fixture(scope='function')
def sample_host(db_session, sample_scan):
    """Create and persist a sample Host linked to a scan.

    Args:
        db_session: The database session fixture.
        sample_scan: The parent Scan fixture.

    Returns:
        Persisted Host instance associated with sample_scan.
    """
    host = Host(
        ip_address='192.168.1.100',
        hostname='webserver.local',
        mac_address='AA:BB:CC:DD:EE:FF',
        os_guess='Linux 5.x',
        os_confidence=85,
        status='up',
        discovery_method='arp',
        risk_score=7.5,
        scan_id=sample_scan.id
    )
    db_session.session.add(host)
    db_session.session.commit()
    return host


@pytest.fixture(scope='function')
def sample_port(db_session, sample_host):
    """Create and persist a sample Port on a host.

    Args:
        db_session: The database session fixture.
        sample_host: The parent Host fixture.

    Returns:
        Persisted Port instance associated with sample_host.
    """
    port = Port(
        host_id=sample_host.id,
        port_number=80,
        protocol='tcp',
        state='open',
        service_name='http',
        service_version='Apache/2.4.52',
        banner='Apache/2.4.52 (Ubuntu)',
        tunnel=None,
        confidence=90
    )
    db_session.session.add(port)
    db_session.session.commit()
    return port


@pytest.fixture(scope='function')
def sample_vulnerability(db_session, sample_scan, sample_host):
    """Create and persist a sample Vulnerability.

    Args:
        db_session: The database session fixture.
        sample_scan: The parent Scan fixture.
        sample_host: The parent Host fixture.

    Returns:
        Persisted Vulnerability instance linked to both scan and host.
    """
    vuln = Vulnerability(
        host_id=sample_host.id,
        scan_id=sample_scan.id,
        title='Unencrypted Telnet Service Exposed',
        description='Telnet service is running on port 23, transmitting credentials in plaintext.',
        severity='high',
        category='insecure_protocol',
        cvss_score=8.1,
        confidence=0.95,
        evidence='Port 23/tcp open, banner: "Login:"',
        remediation='Disable Telnet and migrate to SSH for remote administration.',
        status='open',
        affected_service='telnet',
        affected_port=23,
        reference_urls=['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10188']
    )
    db_session.session.add(vuln)
    db_session.session.commit()
    return vuln


@pytest.fixture(scope='function')
def sample_attack_path(db_session, sample_scan):
    """Create and persist a sample AttackPath.

    Args:
        db_session: The database session fixture.
        sample_scan: The parent Scan fixture.

    Returns:
        Persisted AttackPath instance with a realistic attack chain.
    """
    attack_path = AttackPath(
        scan_id=sample_scan.id,
        name='External to Internal Database Access',
        description='Attacker exploits exposed web server to pivot into internal database.',
        chain=[
            {'host': '192.168.1.100', 'action': 'exploit', 'service': 'http',
             'vulnerability': 'SQL Injection'},
            {'host': '192.168.1.100', 'action': 'escalate', 'service': 'ssh',
             'vulnerability': 'Weak credentials'},
            {'host': '192.168.1.200', 'action': 'pivot', 'service': 'mysql',
             'vulnerability': 'Default credentials'}
        ],
        risk_score=9.2,
        likelihood=0.7,
        impact=0.95,
        entry_point='192.168.1.100:80',
        target_asset='192.168.1.200:3306',
        path_length=3,
        attack_complexity='medium',
        requires_authentication=False,
    )
    db_session.session.add(attack_path)
    db_session.session.commit()
    return attack_path


@pytest.fixture(scope='function')
def sample_security_debt(db_session, sample_scan):
    """Create and persist a sample SecurityDebt assessment.

    Args:
        db_session: The database session fixture.
        sample_scan: The parent Scan fixture.

    Returns:
        Persisted SecurityDebt instance with component scores.
    """
    debt = SecurityDebt(
        scan_id=sample_scan.id,
        debt_score=65.5,
        vulnerability_debt=25.0,
        legacy_service_debt=15.5,
        exposure_debt=12.0,
        configuration_debt=13.0,
        trend='degrading',
        trend_percentage=8.5,
        details={
            'open_critical': 3,
            'open_high': 8,
            'legacy_services': ['telnet', 'ftp'],
            'exposed_ports': 12
        },
        recommendations=[
            {'priority': 'critical', 'action': 'Disable Telnet on all hosts'},
            {'priority': 'high', 'action': 'Update Apache to latest version'},
            {'priority': 'medium', 'action': 'Implement network segmentation'}
        ]
    )
    db_session.session.add(debt)
    db_session.session.commit()
    return debt


@pytest.fixture(scope='function')
def sample_report(db_session, sample_scan):
    """Create and persist a sample Report record.

    Args:
        db_session: The database session fixture.
        sample_scan: The parent Scan fixture.

    Returns:
        Persisted Report instance in pending state.
    """
    report = Report(
        scan_id=sample_scan.id,
        name='Security Assessment Report - Q1 2026',
        report_type='technical',
        format='pdf',
        status='pending',
        include_findings=True,
        include_attack_paths=True,
        include_remediation=True,
        include_executive_summary=True
    )
    db_session.session.add(report)
    db_session.session.commit()
    return report
