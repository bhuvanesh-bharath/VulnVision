"""
VulnVision Model Tests.
Comprehensive tests for all SQLAlchemy models including creation,
field validation, lifecycle methods, computed properties, and serialization.
"""
import pytest
from datetime import datetime, timezone, timedelta

from backend.models import (
    Scan, Host, Port, Vulnerability, AttackPath, SecurityDebt, Report, AuditLog
)
from backend.models.base import db


class TestScanModel:
    """Tests for the Scan model."""

    def test_scan_creation(self, db_session, sample_scan):
        """Verify a Scan is created with all fields correctly populated."""
        assert sample_scan.id is not None
        assert sample_scan.scan_id is not None
        assert len(sample_scan.scan_id) == 36
        assert sample_scan.name == 'Test Network Scan'
        assert sample_scan.target == '192.168.1.0/24'
        assert sample_scan.scan_type == 'quick'
        assert sample_scan.status == 'completed'
        assert sample_scan.progress == 100
        assert sample_scan.hosts_discovered == 5
        assert sample_scan.vulnerabilities_found == 12
        assert sample_scan.ports_scanned == 1000
        assert sample_scan.start_time is not None
        assert sample_scan.end_time is not None
        assert sample_scan.configuration == {'ports': '1-1024', 'timeout': 5}
        assert sample_scan.error_message is None

    def test_scan_lifecycle_start(self, db_session):
        """Verify start() sets status to running and records start_time."""
        scan = Scan(name='Lifecycle Test', target='10.0.0.1', scan_type='quick')
        db_session.session.add(scan)
        db_session.session.commit()

        assert scan.status == 'pending'
        assert scan.start_time is None

        scan.start()
        db_session.session.commit()

        assert scan.status == 'running'
        assert scan.start_time is not None
        assert scan.progress == 0

    def test_scan_lifecycle_complete(self, db_session):
        """Verify complete() sets status to completed, progress to 100, and records end_time."""
        scan = Scan(name='Complete Test', target='10.0.0.1', scan_type='full')
        db_session.session.add(scan)
        db_session.session.commit()

        scan.start()
        scan.complete()
        db_session.session.commit()

        assert scan.status == 'completed'
        assert scan.progress == 100
        assert scan.end_time is not None

    def test_scan_lifecycle_fail(self, db_session):
        """Verify fail() sets status to failed and stores the error message."""
        scan = Scan(name='Fail Test', target='10.0.0.1', scan_type='quick')
        db_session.session.add(scan)
        db_session.session.commit()

        scan.start()
        scan.fail(error_message='Connection refused by target host')
        db_session.session.commit()

        assert scan.status == 'failed'
        assert scan.error_message == 'Connection refused by target host'
        assert scan.end_time is not None

    def test_scan_lifecycle_cancel(self, db_session):
        """Verify cancel() sets status to cancelled and records end_time."""
        scan = Scan(name='Cancel Test', target='10.0.0.1', scan_type='quick')
        db_session.session.add(scan)
        db_session.session.commit()

        scan.start()
        scan.cancel()
        db_session.session.commit()

        assert scan.status == 'cancelled'
        assert scan.end_time is not None

    def test_scan_duration(self, db_session, sample_scan):
        """Verify duration_seconds returns correct elapsed time for completed scans."""
        duration = sample_scan.duration_seconds
        assert duration is not None
        # 5 minutes and 30 seconds = 330.0 seconds
        assert duration == 330.0

    def test_scan_duration_no_end_time(self, db_session):
        """Verify duration_seconds calculates running duration when no end_time."""
        scan = Scan(name='Running Scan', target='10.0.0.1', scan_type='quick')
        db_session.session.add(scan)
        db_session.session.commit()

        scan.start()
        db_session.session.commit()

        duration = scan.duration_seconds
        assert duration is not None
        assert duration >= 0

    def test_scan_duration_not_started(self, db_session):
        """Verify duration_seconds returns None when scan hasn't started."""
        scan = Scan(name='Pending Scan', target='10.0.0.1', scan_type='quick')
        db_session.session.add(scan)
        db_session.session.commit()

        assert scan.duration_seconds is None

    def test_scan_serialization(self, db_session, sample_scan):
        """Verify to_dict() produces a dictionary with all fields and computed values."""
        data = sample_scan.to_dict()

        assert isinstance(data, dict)
        assert data['name'] == 'Test Network Scan'
        assert data['target'] == '192.168.1.0/24'
        assert data['scan_type'] == 'quick'
        assert data['status'] == 'completed'
        assert data['progress'] == 100
        assert data['hosts_discovered'] == 5
        assert data['vulnerabilities_found'] == 12
        assert 'duration_seconds' in data
        assert data['duration_seconds'] == 330.0
        assert 'host_count' in data
        assert 'vulnerability_count' in data
        assert data['scan_id'] is not None

    def test_scan_repr(self, db_session, sample_scan):
        """Verify string representation includes key identifiers."""
        repr_str = repr(sample_scan)
        assert 'Scan' in repr_str
        assert sample_scan.scan_id in repr_str
        assert '192.168.1.0/24' in repr_str

    def test_scan_valid_statuses(self):
        """Verify the set of valid scan statuses."""
        assert 'pending' in Scan.VALID_STATUSES
        assert 'running' in Scan.VALID_STATUSES
        assert 'completed' in Scan.VALID_STATUSES
        assert 'failed' in Scan.VALID_STATUSES
        assert 'cancelled' in Scan.VALID_STATUSES

    def test_scan_valid_types(self):
        """Verify the set of valid scan types."""
        assert 'quick' in Scan.VALID_TYPES
        assert 'full' in Scan.VALID_TYPES
        assert 'custom' in Scan.VALID_TYPES
        assert 'targeted' in Scan.VALID_TYPES


class TestHostModel:
    """Tests for the Host model."""

    def test_host_creation(self, db_session, sample_host):
        """Verify a Host is created with all fields correctly populated."""
        assert sample_host.id is not None
        assert sample_host.host_id is not None
        assert len(sample_host.host_id) == 36
        assert sample_host.ip_address == '192.168.1.100'
        assert sample_host.hostname == 'webserver.local'
        assert sample_host.mac_address == 'AA:BB:CC:DD:EE:FF'
        assert sample_host.os_guess == 'Linux 5.x'
        assert sample_host.os_confidence == 85
        assert sample_host.status == 'up'
        assert sample_host.discovery_method == 'arp'
        assert sample_host.risk_score == 7.5
        assert sample_host.scan_id is not None

    def test_host_relationships(self, db_session, sample_host, sample_port, sample_vulnerability):
        """Verify Host has correct relationships to Ports and Vulnerabilities."""
        assert sample_host.ports is not None
        assert sample_host.ports.count() == 1
        assert sample_host.vulnerabilities is not None
        assert sample_host.vulnerabilities.count() == 1

        port = sample_host.ports.first()
        assert port.port_number == 80

        vuln = sample_host.vulnerabilities.first()
        assert vuln.severity == 'high'

    def test_host_scan_relationship(self, db_session, sample_scan, sample_host):
        """Verify Host is linked to its parent Scan."""
        assert sample_host.scan_id == sample_scan.id
        assert sample_host.scan.name == 'Test Network Scan'

    def test_host_serialization(self, db_session, sample_host):
        """Verify to_dict() includes computed port and vulnerability counts."""
        data = sample_host.to_dict()
        assert isinstance(data, dict)
        assert data['ip_address'] == '192.168.1.100'
        assert 'open_port_count' in data
        assert 'vulnerability_count' in data

    def test_host_repr(self, db_session, sample_host):
        """Verify string representation of Host."""
        repr_str = repr(sample_host)
        assert 'Host' in repr_str
        assert '192.168.1.100' in repr_str


class TestPortModel:
    """Tests for the Port model."""

    def test_port_creation(self, db_session, sample_port):
        """Verify a Port is created with all fields correctly populated."""
        assert sample_port.id is not None
        assert sample_port.port_number == 80
        assert sample_port.protocol == 'tcp'
        assert sample_port.state == 'open'
        assert sample_port.service_name == 'http'
        assert sample_port.service_version == 'Apache/2.4.52'
        assert sample_port.banner == 'Apache/2.4.52 (Ubuntu)'
        assert sample_port.confidence == 90

    def test_port_display_name(self, db_session, sample_port):
        """Verify display_name combines port number, protocol, and service."""
        assert sample_port.display_name == '80/tcp (http)'

    def test_port_display_name_no_service(self, db_session, sample_host):
        """Verify display_name without a service name."""
        port = Port(
            host_id=sample_host.id,
            port_number=9999,
            protocol='tcp',
            state='open'
        )
        db_session.session.add(port)
        db_session.session.commit()

        assert port.display_name == '9999/tcp'

    def test_port_is_open(self, db_session, sample_port):
        """Verify is_open property returns True for open ports."""
        assert sample_port.is_open is True

    def test_port_is_not_open(self, db_session, sample_host):
        """Verify is_open returns False for closed ports."""
        port = Port(
            host_id=sample_host.id,
            port_number=443,
            protocol='tcp',
            state='closed'
        )
        db_session.session.add(port)
        db_session.session.commit()

        assert port.is_open is False

    def test_port_serialization(self, db_session, sample_port):
        """Verify to_dict() includes display_name and is_open."""
        data = sample_port.to_dict()
        assert data['display_name'] == '80/tcp (http)'
        assert data['is_open'] is True
        assert data['port_number'] == 80


class TestVulnerabilityModel:
    """Tests for the Vulnerability model."""

    def test_vulnerability_creation(self, db_session, sample_vulnerability):
        """Verify a Vulnerability is created with all fields correctly populated."""
        vuln = sample_vulnerability
        assert vuln.id is not None
        assert vuln.vuln_id is not None
        assert len(vuln.vuln_id) == 36
        assert vuln.title == 'Unencrypted Telnet Service Exposed'
        assert vuln.severity == 'high'
        assert vuln.category == 'insecure_protocol'
        assert vuln.cvss_score == 8.1
        assert vuln.confidence == 0.95
        assert vuln.status == 'open'
        assert vuln.affected_service == 'telnet'
        assert vuln.affected_port == 23
        assert isinstance(vuln.reference_urls, list)
        assert len(vuln.reference_urls) == 1

    def test_vulnerability_severity_rank(self, db_session, sample_host, sample_scan):
        """Verify severity_rank returns correct ordering for all severities."""
        severities = {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }

        for severity, expected_rank in severities.items():
            vuln = Vulnerability(
                host_id=sample_host.id,
                scan_id=sample_scan.id,
                title=f'Test {severity}',
                description=f'Test vulnerability with {severity} severity',
                severity=severity,
                cvss_score=5.0,
                confidence=0.5
            )
            assert vuln.severity_rank == expected_rank

    def test_vulnerability_risk_score(self, db_session, sample_vulnerability):
        """Verify risk_score computed property uses severity weight * confidence."""
        # high severity weight = 7.5, confidence = 0.95
        expected = round(7.5 * 0.95, 2)
        assert sample_vulnerability.risk_score == expected

    def test_vulnerability_risk_score_critical(self, db_session, sample_host, sample_scan):
        """Verify risk_score for critical severity vulnerability."""
        vuln = Vulnerability(
            host_id=sample_host.id,
            scan_id=sample_scan.id,
            title='Critical Vuln',
            description='A critical vulnerability',
            severity='critical',
            cvss_score=9.8,
            confidence=1.0
        )
        # critical weight = 10.0, confidence = 1.0
        assert vuln.risk_score == 10.0

    def test_vulnerability_risk_score_info(self, db_session, sample_host, sample_scan):
        """Verify risk_score for info severity vulnerability."""
        vuln = Vulnerability(
            host_id=sample_host.id,
            scan_id=sample_scan.id,
            title='Info Finding',
            description='An informational finding',
            severity='info',
            cvss_score=0.0,
            confidence=0.8
        )
        # info weight = 0.5, confidence = 0.8
        expected = round(0.5 * 0.8, 2)
        assert vuln.risk_score == expected

    def test_vulnerability_lifecycle_resolve(self, db_session, sample_vulnerability):
        """Verify resolve() sets status and resolved_at timestamp."""
        assert sample_vulnerability.status == 'open'
        assert sample_vulnerability.is_active is True

        sample_vulnerability.resolve()
        db_session.session.commit()

        assert sample_vulnerability.status == 'resolved'
        assert sample_vulnerability.resolved_at is not None
        assert sample_vulnerability.is_active is False

    def test_vulnerability_lifecycle_accept(self, db_session, sample_vulnerability):
        """Verify accept_risk() sets status to accepted."""
        sample_vulnerability.accept_risk()
        db_session.session.commit()

        assert sample_vulnerability.status == 'accepted'
        assert sample_vulnerability.is_active is False

    def test_vulnerability_lifecycle_false_positive(self, db_session, sample_vulnerability):
        """Verify mark_false_positive() sets status to false_positive."""
        sample_vulnerability.mark_false_positive()
        db_session.session.commit()

        assert sample_vulnerability.status == 'false_positive'
        assert sample_vulnerability.is_active is False

    def test_vulnerability_serialization(self, db_session, sample_vulnerability):
        """Verify to_dict() includes computed risk_score, is_active, and severity_rank."""
        data = sample_vulnerability.to_dict()
        assert isinstance(data, dict)
        assert data['title'] == 'Unencrypted Telnet Service Exposed'
        assert 'risk_score' in data
        assert 'is_active' in data
        assert 'severity_rank' in data
        assert data['is_active'] is True
        assert data['severity_rank'] == 1  # high


class TestAttackPathModel:
    """Tests for the AttackPath model."""

    def test_attack_path_creation(self, db_session, sample_attack_path):
        """Verify an AttackPath is created with all fields correctly populated."""
        ap = sample_attack_path
        assert ap.id is not None
        assert ap.path_id is not None
        assert len(ap.path_id) == 36
        assert ap.name == 'External to Internal Database Access'
        assert ap.risk_score == 9.2
        assert ap.likelihood == 0.7
        assert ap.impact == 0.95
        assert ap.entry_point == '192.168.1.100:80'
        assert ap.target_asset == '192.168.1.200:3306'
        assert ap.path_length == 3
        assert ap.attack_complexity == 'medium'
        assert ap.requires_authentication is False
        assert isinstance(ap.chain, list)
        assert len(ap.chain) == 3

    def test_attack_path_composite_score(self, db_session, sample_attack_path):
        """Verify composite_score combines likelihood (40%) and impact (60%)."""
        # (0.7 * 0.4 + 0.95 * 0.6) * 10 = (0.28 + 0.57) * 10 = 8.5
        expected = round((0.7 * 0.4 + 0.95 * 0.6) * 10, 2)
        assert sample_attack_path.composite_score == expected

    def test_attack_path_composite_score_zero(self, db_session, sample_scan):
        """Verify composite_score is zero when likelihood and impact are zero."""
        ap = AttackPath(
            scan_id=sample_scan.id,
            name='Zero Risk Path',
            chain=[],
            risk_score=0.0,
            likelihood=0.0,
            impact=0.0,
            path_length=0,
            attack_complexity='low'
        )
        assert ap.composite_score == 0.0

    def test_attack_path_chain_summary(self, db_session, sample_attack_path):
        """Verify chain_summary produces a readable multi-step description."""
        summary = sample_attack_path.chain_summary
        assert 'Step 1' in summary
        assert 'Step 2' in summary
        assert 'Step 3' in summary
        assert 'exploit' in summary
        assert '192.168.1.100' in summary
        assert '→' in summary

    def test_attack_path_chain_summary_empty(self, db_session, sample_scan):
        """Verify chain_summary returns default text for empty chains."""
        ap = AttackPath(
            scan_id=sample_scan.id,
            name='Empty Path',
            chain=[],
            risk_score=0.0,
            likelihood=0.0,
            impact=0.0,
            path_length=0,
            attack_complexity='low'
        )
        assert ap.chain_summary == 'No steps defined'

    def test_attack_path_serialization(self, db_session, sample_attack_path):
        """Verify to_dict() includes composite_score and chain_summary."""
        data = sample_attack_path.to_dict()
        assert isinstance(data, dict)
        assert 'composite_score' in data
        assert 'chain_summary' in data
        assert data['name'] == 'External to Internal Database Access'


class TestSecurityDebtModel:
    """Tests for the SecurityDebt model."""

    def test_security_debt_creation(self, db_session, sample_security_debt):
        """Verify a SecurityDebt is created with all fields correctly populated."""
        debt = sample_security_debt
        assert debt.id is not None
        assert debt.debt_id is not None
        assert len(debt.debt_id) == 36
        assert debt.debt_score == 65.5
        assert debt.vulnerability_debt == 25.0
        assert debt.legacy_service_debt == 15.5
        assert debt.exposure_debt == 12.0
        assert debt.configuration_debt == 13.0
        assert debt.trend == 'degrading'
        assert debt.trend_percentage == 8.5
        assert isinstance(debt.details, dict)
        assert isinstance(debt.recommendations, list)
        assert len(debt.recommendations) == 3

    def test_security_debt_rating_critical(self, db_session, sample_scan):
        """Verify debt_rating returns 'critical' for scores >= 80."""
        debt = SecurityDebt(
            scan_id=sample_scan.id,
            debt_score=85.0,
            vulnerability_debt=40.0,
            legacy_service_debt=20.0,
            exposure_debt=15.0,
            configuration_debt=10.0
        )
        assert debt.debt_rating == 'critical'

    def test_security_debt_rating_high(self, db_session, sample_security_debt):
        """Verify debt_rating returns 'high' for scores >= 60 and < 80."""
        # sample_security_debt has debt_score=65.5
        assert sample_security_debt.debt_rating == 'high'

    def test_security_debt_rating_medium(self, db_session, sample_scan):
        """Verify debt_rating returns 'medium' for scores >= 40 and < 60."""
        debt = SecurityDebt(
            scan_id=sample_scan.id,
            debt_score=45.0,
            vulnerability_debt=15.0,
            legacy_service_debt=10.0,
            exposure_debt=10.0,
            configuration_debt=10.0
        )
        assert debt.debt_rating == 'medium'

    def test_security_debt_rating_low(self, db_session, sample_scan):
        """Verify debt_rating returns 'low' for scores >= 20 and < 40."""
        debt = SecurityDebt(
            scan_id=sample_scan.id,
            debt_score=25.0,
            vulnerability_debt=10.0,
            legacy_service_debt=5.0,
            exposure_debt=5.0,
            configuration_debt=5.0
        )
        assert debt.debt_rating == 'low'

    def test_security_debt_rating_minimal(self, db_session, sample_scan):
        """Verify debt_rating returns 'minimal' for scores < 20."""
        debt = SecurityDebt(
            scan_id=sample_scan.id,
            debt_score=10.0,
            vulnerability_debt=3.0,
            legacy_service_debt=3.0,
            exposure_debt=2.0,
            configuration_debt=2.0
        )
        assert debt.debt_rating == 'minimal'

    def test_security_debt_breakdown(self, db_session, sample_security_debt):
        """Verify debt_breakdown returns correct component percentages."""
        breakdown = sample_security_debt.debt_breakdown
        assert isinstance(breakdown, dict)
        assert 'vulnerability' in breakdown
        assert 'legacy_service' in breakdown
        assert 'exposure' in breakdown
        assert 'configuration' in breakdown

        assert breakdown['vulnerability']['score'] == 25.0
        assert breakdown['legacy_service']['score'] == 15.5
        assert breakdown['exposure']['score'] == 12.0
        assert breakdown['configuration']['score'] == 13.0

        # Verify percentages are calculated against total debt_score (65.5)
        vuln_pct = round((25.0 / 65.5) * 100, 1)
        assert breakdown['vulnerability']['percentage'] == vuln_pct

    def test_security_debt_serialization(self, db_session, sample_security_debt):
        """Verify to_dict() includes debt_rating and debt_breakdown."""
        data = sample_security_debt.to_dict()
        assert isinstance(data, dict)
        assert 'debt_rating' in data
        assert 'debt_breakdown' in data
        assert data['debt_score'] == 65.5


class TestReportModel:
    """Tests for the Report model."""

    def test_report_creation(self, db_session, sample_report):
        """Verify a Report is created with all fields correctly populated."""
        report = sample_report
        assert report.id is not None
        assert report.report_id is not None
        assert len(report.report_id) == 36
        assert report.name == 'Security Assessment Report - Q1 2026'
        assert report.report_type == 'technical'
        assert report.format == 'pdf'
        assert report.status == 'pending'
        assert report.include_findings is True
        assert report.include_attack_paths is True
        assert report.include_remediation is True
        assert report.include_executive_summary is True
        assert report.file_path is None
        assert report.generated_at is None

    def test_report_lifecycle_generating(self, db_session, sample_report):
        """Verify mark_generating() transitions status to generating."""
        sample_report.mark_generating()
        db_session.session.commit()

        assert sample_report.status == 'generating'

    def test_report_lifecycle_completed(self, db_session, sample_report):
        """Verify mark_completed() sets file path, size, and timestamp."""
        sample_report.mark_generating()
        sample_report.mark_completed(
            file_path='/exports/pdf/report_2026.pdf',
            file_size=1048576  # 1 MB
        )
        db_session.session.commit()

        assert sample_report.status == 'completed'
        assert sample_report.file_path == '/exports/pdf/report_2026.pdf'
        assert sample_report.file_size == 1048576
        assert sample_report.generated_at is not None

    def test_report_lifecycle_failed(self, db_session, sample_report):
        """Verify mark_failed() sets error message."""
        sample_report.mark_generating()
        sample_report.mark_failed('PDF rendering engine timeout')
        db_session.session.commit()

        assert sample_report.status == 'failed'
        assert sample_report.error_message == 'PDF rendering engine timeout'

    def test_report_file_size_display(self, db_session, sample_report):
        """Verify file_size_display returns human-readable file sizes."""
        sample_report.file_size = 0
        assert sample_report.file_size_display == '0 B'

        sample_report.file_size = 512
        assert sample_report.file_size_display == '512.0 B'

        sample_report.file_size = 1024
        assert sample_report.file_size_display == '1.0 KB'

        sample_report.file_size = 1048576
        assert sample_report.file_size_display == '1.0 MB'

        sample_report.file_size = 1073741824
        assert sample_report.file_size_display == '1.0 GB'

    def test_report_serialization(self, db_session, sample_report):
        """Verify to_dict() includes file_size_display."""
        data = sample_report.to_dict()
        assert isinstance(data, dict)
        assert 'file_size_display' in data
        assert data['name'] == 'Security Assessment Report - Q1 2026'

    def test_report_valid_types(self):
        """Verify the set of valid report types."""
        assert 'executive' in Report.VALID_TYPES
        assert 'technical' in Report.VALID_TYPES
        assert 'compliance' in Report.VALID_TYPES
        assert 'full' in Report.VALID_TYPES

    def test_report_valid_formats(self):
        """Verify the set of valid report formats."""
        assert 'pdf' in Report.VALID_FORMATS
        assert 'csv' in Report.VALID_FORMATS
        assert 'json' in Report.VALID_FORMATS


class TestAuditLogModel:
    """Tests for the AuditLog model."""

    def test_audit_log_creation(self, db_session):
        """Verify an AuditLog entry is created with all fields."""
        log = AuditLog(
            action='scan_created',
            entity_type='scan',
            entity_id='abc-123',
            details='New scan initiated for 192.168.1.0/24',
            ip_address='127.0.0.1',
            user_agent='Mozilla/5.0'
        )
        db_session.session.add(log)
        db_session.session.commit()

        assert log.id is not None
        assert log.action == 'scan_created'
        assert log.entity_type == 'scan'
        assert log.entity_id == 'abc-123'
        assert log.details == 'New scan initiated for 192.168.1.0/24'
        assert log.ip_address == '127.0.0.1'
        assert log.user_agent == 'Mozilla/5.0'
        assert log.timestamp is not None

    def test_audit_log_class_method(self, db_session):
        """Verify AuditLog.log() creates and persists an entry in one step."""
        entry = AuditLog.log(
            action='scan_completed',
            entity_type='scan',
            entity_id='def-456',
            details='Scan completed with 5 findings',
            ip_address='10.0.0.1',
            user_agent='VulnVision/1.0'
        )

        assert entry.id is not None
        assert entry.action == 'scan_completed'
        assert entry.entity_id == 'def-456'

        # Verify it's persisted in the database
        fetched = db_session.session.get(AuditLog, entry.id)
        assert fetched is not None
        assert fetched.action == 'scan_completed'

    def test_audit_log_repr(self, db_session):
        """Verify string representation of AuditLog."""
        log = AuditLog(
            action='vulnerability_detected',
            entity_type='vulnerability',
            entity_id='vuln-789'
        )
        repr_str = repr(log)
        assert 'AuditLog' in repr_str
        assert 'vulnerability_detected' in repr_str

    def test_audit_log_actions(self):
        """Verify the predefined action constants are available."""
        assert AuditLog.ACTIONS['SCAN_CREATED'] == 'scan_created'
        assert AuditLog.ACTIONS['SCAN_COMPLETED'] == 'scan_completed'
        assert AuditLog.ACTIONS['VULN_DETECTED'] == 'vulnerability_detected'
        assert AuditLog.ACTIONS['REPORT_GENERATED'] == 'report_generated'


class TestModelRelationships:
    """Cross-model relationship integrity tests."""

    def test_scan_cascade_delete_hosts(self, db_session, sample_scan, sample_host):
        """Verify deleting a Scan cascades to its Hosts."""
        host_id = sample_host.id
        db_session.session.delete(sample_scan)
        db_session.session.commit()

        assert db_session.session.get(Host, host_id) is None

    def test_scan_cascade_delete_vulnerabilities(
        self, db_session, sample_scan, sample_host, sample_vulnerability
    ):
        """Verify deleting a Scan cascades to its Vulnerabilities."""
        vuln_id = sample_vulnerability.id
        db_session.session.delete(sample_scan)
        db_session.session.commit()

        assert db_session.session.get(Vulnerability, vuln_id) is None

    def test_host_cascade_delete_ports(self, db_session, sample_host, sample_port):
        """Verify deleting a Host cascades to its Ports."""
        port_id = sample_port.id
        db_session.session.delete(sample_host)
        db_session.session.commit()

        assert db_session.session.get(Port, port_id) is None

    def test_scan_hosts_dynamic_relationship(self, db_session, sample_scan):
        """Verify Scan.hosts uses dynamic lazy loading with query interface."""
        host1 = Host(ip_address='10.0.0.1', scan_id=sample_scan.id)
        host2 = Host(ip_address='10.0.0.2', scan_id=sample_scan.id)
        db_session.session.add_all([host1, host2])
        db_session.session.commit()

        assert sample_scan.hosts.count() == 2
        assert sample_scan.hosts.filter_by(ip_address='10.0.0.1').count() == 1
