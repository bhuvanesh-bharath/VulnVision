"""
VulnVision Scanner Component Tests.
Tests for HostDiscovery, PortScanner, ServiceDetector, and OSFingerprint.
"""
import pytest
from backend.services.scanner.host_discovery import HostDiscovery
from backend.services.scanner.port_scanner import PortScanner
from backend.services.scanner.service_detector import ServiceDetector
from backend.services.scanner.os_fingerprint import OSFingerprint


class TestHostDiscovery:
    """Tests for HostDiscovery target parsing."""

    def setup_method(self):
        self.discovery = HostDiscovery()

    def test_parse_target_single_ip(self):
        result = self.discovery._parse_target('192.168.1.1')
        assert result == ['192.168.1.1']

    def test_parse_target_cidr_small(self):
        result = self.discovery._parse_target('192.168.1.0/30')
        assert '192.168.1.1' in result
        assert '192.168.1.2' in result
        assert len(result) == 2

    def test_parse_target_cidr_24(self):
        result = self.discovery._parse_target('192.168.1.0/24')
        assert len(result) == 254
        assert '192.168.1.1' in result
        assert '192.168.1.254' in result
        assert '192.168.1.0' not in result
        assert '192.168.1.255' not in result

    def test_parse_target_range(self):
        result = self.discovery._parse_target('192.168.1.1-10')
        assert len(result) == 10
        assert '192.168.1.1' in result
        assert '192.168.1.10' in result

    def test_parse_target_comma_list(self):
        result = self.discovery._parse_target('192.168.1.1,192.168.1.2,192.168.1.3')
        assert len(result) == 3
        assert '192.168.1.1' in result
        assert '192.168.1.3' in result

    def test_parse_target_invalid(self):
        result = self.discovery._parse_target('not_an_ip_or_host_999')
        assert result == []


class TestPortScanner:
    """Tests for PortScanner port range parsing."""

    def setup_method(self):
        self.scanner = PortScanner()

    def test_parse_port_range_default(self):
        result = self.scanner._parse_port_range('default')
        assert len(result) > 0
        assert 80 in result
        assert 443 in result

    def test_parse_port_range_single(self):
        result = self.scanner._parse_port_range('80')
        assert result == [80]

    def test_parse_port_range_range(self):
        result = self.scanner._parse_port_range('1-100')
        assert len(result) == 100
        assert result[0] == 1
        assert result[-1] == 100

    def test_parse_port_range_list(self):
        result = self.scanner._parse_port_range('80,443,8080')
        assert sorted(result) == [80, 443, 8080]

    def test_parse_port_range_mixed(self):
        result = self.scanner._parse_port_range('22,80,100-105')
        assert 22 in result
        assert 80 in result
        assert 100 in result
        assert 105 in result

    def test_parse_port_range_full(self):
        result = self.scanner._parse_port_range('full')
        assert len(result) == 65535

    def test_parse_port_range_invalid(self):
        result = self.scanner._parse_port_range('abc')
        assert result == []


class TestServiceDetector:
    """Tests for ServiceDetector identification."""

    def setup_method(self):
        self.detector = ServiceDetector()

    def test_identify_by_port_http(self):
        result = self.detector._identify_by_port(80)
        assert result['service_name'] == 'http'
        assert result['confidence'] == 50

    def test_identify_by_port_ssh(self):
        result = self.detector._identify_by_port(22)
        assert result['service_name'] == 'ssh'

    def test_identify_by_port_ftp(self):
        result = self.detector._identify_by_port(21)
        assert result['service_name'] == 'ftp'

    def test_identify_by_port_mysql(self):
        result = self.detector._identify_by_port(3306)
        assert result['service_name'] == 'mysql'

    def test_identify_by_port_unknown(self):
        result = self.detector._identify_by_port(54321)
        assert 'unknown' in result['service_name']
        assert result['confidence'] == 10

    def test_identify_by_banner_openssh(self):
        result = self.detector._identify_by_banner('SSH-2.0-OpenSSH_8.9')
        assert result['service_name'] == 'ssh'
        assert 'OpenSSH' in result['service_version']
        assert result['confidence'] >= 75

    def test_identify_by_banner_apache(self):
        result = self.detector._identify_by_banner('Server: Apache/2.4.52')
        assert result['service_name'] == 'http'
        assert 'Apache' in result['service_version']

    def test_identify_by_banner_nginx(self):
        result = self.detector._identify_by_banner('Server: nginx/1.22.0')
        assert result['service_name'] == 'http'
        assert 'nginx' in result['service_version']

    def test_identify_by_banner_vsftpd(self):
        result = self.detector._identify_by_banner('220 (vsFTPd 3.0.5)')
        assert result['service_name'] == 'ftp'
        assert 'vsftpd' in result['service_version']

    def test_identify_by_banner_empty(self):
        result = self.detector._identify_by_banner('')
        assert result['service_name'] is None
        assert result['confidence'] == 0

    def test_identify_by_banner_none(self):
        result = self.detector._identify_by_banner(None)
        assert result['confidence'] == 0


class TestOSFingerprint:
    """Tests for OSFingerprint analysis."""

    def setup_method(self):
        self.fingerprint = OSFingerprint()

    def test_analyze_ports_windows(self):
        candidates = self.fingerprint._analyze_ports([135, 139, 445, 3389])
        os_names = [c['os'] for c in candidates]
        assert any('Windows' in name for name in os_names)

    def test_analyze_ports_linux(self):
        candidates = self.fingerprint._analyze_ports([22, 80, 443])
        os_names = [c['os'] for c in candidates]
        assert any('Linux' in name for name in os_names)

    def test_analyze_banners_windows(self):
        candidates = self.fingerprint._analyze_banners({
            445: 'Microsoft Windows Server 2019'
        })
        os_names = [c['os'] for c in candidates]
        assert any('Windows' in name for name in os_names)

    def test_analyze_banners_linux(self):
        candidates = self.fingerprint._analyze_banners({
            22: 'SSH-2.0-OpenSSH_8.9 Ubuntu'
        })
        os_names = [c['os'] for c in candidates]
        assert any('Linux' in name or 'Ubuntu' in name for name in os_names)

    def test_calculate_confidence_empty(self):
        result = self.fingerprint._calculate_confidence([])
        assert result['os_guess'] == 'Unknown'
        assert result['confidence'] == 0

    def test_calculate_confidence_single(self):
        result = self.fingerprint._calculate_confidence([
            {'os': 'Windows', 'confidence': 70, 'source': 'ports'}
        ])
        assert result['os_guess'] == 'Windows'
        assert result['confidence'] == 70

    def test_estimate_os_complete(self):
        result = self.fingerprint.estimate_os(
            '192.168.1.1',
            [135, 139, 445, 3389],
            {445: 'Microsoft Windows'}
        )
        assert 'os_guess' in result
        assert 'os_family' in result
        assert 'confidence' in result
        assert result['confidence'] > 0
