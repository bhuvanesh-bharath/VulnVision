"""
VulnVision Network Scanner Orchestrator.
Coordinates host discovery, port scanning, service detection, and OS fingerprinting.
"""
from datetime import datetime, timezone
from backend.models.base import db
from backend.models.scan import Scan
from backend.models.host import Host
from backend.models.port import Port
from backend.services.scanner.host_discovery import HostDiscovery
from backend.services.scanner.port_scanner import PortScanner
from backend.services.scanner.service_detector import ServiceDetector
from backend.services.scanner.os_fingerprint import OSFingerprint
from backend.utils.logger import get_scan_logger
from backend.utils.exceptions import ScanError

logger = get_scan_logger()


class NetworkScanner:
    """Main network scanner orchestrating all scanning components."""

    def __init__(self):
        self.host_discovery = HostDiscovery()
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.os_fingerprint = OSFingerprint()

    def execute_scan(self, scan_id, target, scan_type, configuration=None):
        """Execute a complete network scan pipeline.

        Args:
            scan_id: Database ID of the Scan record.
            target: Target IP/CIDR/range string.
            scan_type: Scan type ('quick', 'full', 'custom', 'targeted').
            configuration: Optional scan configuration dict.

        Returns:
            Dict with scan results summary.
        """
        scan = db.session.get(Scan, scan_id)
        if not scan:
            raise ScanError(f'Scan with ID {scan_id} not found')

        try:
            scan.start()
            db.session.commit()
            logger.info('Starting scan %s: target=%s type=%s', scan.scan_id, target, scan_type)

            ports_config = 'default'
            if configuration:
                ports_config = configuration.get('ports', 'default')
            if scan_type == 'full':
                ports_config = '1-10000'
            elif scan_type == 'quick':
                ports_config = 'default'

            # Step 1: Host Discovery
            scan.progress = 10
            db.session.commit()
            discovered_hosts = self.host_discovery.discover_hosts(target)
            scan.hosts_discovered = len(discovered_hosts)
            scan.progress = 25
            db.session.commit()
            logger.info('Discovered %d hosts', len(discovered_hosts))

            if not discovered_hosts:
                scan.complete()
                db.session.commit()
                return {'hosts_discovered': 0, 'total_ports': 0, 'total_vulnerabilities': 0}

            all_hosts = []
            total_ports = 0
            progress_per_host = 65 / max(len(discovered_hosts), 1)

            for idx, host_data in enumerate(discovered_hosts):
                ip = host_data['ip']
                logger.info('Scanning host %d/%d: %s', idx + 1, len(discovered_hosts), ip)

                # Step 2: Port Scanning
                port_results = self.port_scanner.scan_ports(ip, ports_config)
                open_ports = [p for p in port_results if p['state'] == 'open']

                # Step 3: Service Detection
                banners = {}
                for port_data in open_ports:
                    svc = self.service_detector.detect_service(
                        ip, port_data['port'], port_data.get('banner')
                    )
                    port_data['service_name'] = svc.get('service_name', port_data.get('service_name'))
                    port_data['service_version'] = svc.get('service_version')
                    port_data['confidence'] = svc.get('confidence', 0)
                    if port_data.get('banner'):
                        banners[port_data['port']] = port_data['banner']

                # Step 4: OS Fingerprinting
                open_port_numbers = [p['port'] for p in open_ports]
                os_result = self.os_fingerprint.estimate_os(ip, open_port_numbers, banners)

                # Step 5: Persist to database
                host_record = self._persist_host(scan_id, host_data, os_result)
                ports_created = self._persist_ports(host_record.id, open_ports)
                total_ports += len(ports_created)

                risk = self._calculate_host_risk(host_record, open_ports)
                host_record.risk_score = risk
                db.session.commit()

                all_hosts.append(host_record)
                scan.ports_scanned += len(port_results)
                scan.progress = 25 + int(progress_per_host * (idx + 1))
                db.session.commit()

            # Step 6: Run vulnerability detection
            vuln_count = 0
            try:
                from backend.services.vulnerability.vulnerability_engine import VulnerabilityEngine
                vuln_engine = VulnerabilityEngine()
                vulns = vuln_engine.analyze(scan_id, all_hosts)
                vuln_count = len(vulns)
                scan.vulnerabilities_found = vuln_count
            except Exception as e:
                logger.error('Vulnerability analysis failed: %s', str(e))

            # Step 7: Run attack path generation
            try:
                from backend.services.attack_path.attack_path_engine import AttackPathEngine
                attack_engine = AttackPathEngine()
                attack_engine.generate(scan_id)
            except Exception as e:
                logger.error('Attack path generation failed: %s', str(e))

            # Step 8: Calculate security debt
            try:
                from backend.services.security_debt.debt_engine import SecurityDebtEngine
                debt_engine = SecurityDebtEngine()
                debt_engine.calculate(scan_id)
            except Exception as e:
                logger.error('Security debt calculation failed: %s', str(e))

            scan.complete()
            db.session.commit()
            logger.info('Scan %s completed: %d hosts, %d ports, %d vulns',
                        scan.scan_id, len(all_hosts), total_ports, vuln_count)

            return {
                'hosts_discovered': len(all_hosts),
                'total_ports': total_ports,
                'total_vulnerabilities': vuln_count,
            }

        except Exception as e:
            logger.error('Scan %s failed: %s', scan.scan_id, str(e))
            scan.fail(str(e))
            db.session.commit()
            raise ScanError(f'Scan failed: {str(e)}')

    def _persist_host(self, scan_id, host_data, os_result=None):
        """Create a Host record in the database.

        Args:
            scan_id: Parent scan ID.
            host_data: Dict from host discovery.
            os_result: OS fingerprint result dict.

        Returns:
            Created Host instance.
        """
        host = Host(
            scan_id=scan_id,
            ip_address=host_data['ip'],
            hostname=host_data.get('hostname'),
            mac_address=host_data.get('mac'),
            status=host_data.get('status', 'up'),
            discovery_method=host_data.get('discovery_method', 'unknown'),
            os_guess=os_result.get('os_guess', 'Unknown') if os_result else 'Unknown',
            os_confidence=os_result.get('confidence', 0) if os_result else 0,
        )
        db.session.add(host)
        db.session.commit()
        return host

    def _persist_ports(self, host_id, ports_data):
        """Create Port records for a host.

        Args:
            host_id: Parent host ID.
            ports_data: List of port scan result dicts.

        Returns:
            List of created Port instances.
        """
        ports = []
        for pd in ports_data:
            port = Port(
                host_id=host_id,
                port_number=pd['port'],
                protocol=pd.get('protocol', 'tcp'),
                state=pd.get('state', 'open'),
                service_name=pd.get('service_name'),
                service_version=pd.get('service_version'),
                banner=pd.get('banner'),
                confidence=pd.get('confidence', 0),
            )
            ports.append(port)

        if ports:
            db.session.add_all(ports)
            db.session.commit()
        return ports

    def _calculate_host_risk(self, host, open_ports):
        """Calculate a risk score for a host based on open ports and services.

        Args:
            host: Host instance.
            open_ports: List of open port dicts.

        Returns:
            Float risk score 0-10.
        """
        score = 0.0
        high_risk_ports = {21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017, 161}
        medium_risk_ports = {22, 25, 110, 143, 389, 8080, 8443, 135, 139}

        for pd in open_ports:
            port = pd['port']
            if port in high_risk_ports:
                score += 1.5
            elif port in medium_risk_ports:
                score += 0.8
            else:
                score += 0.3

        port_count_bonus = min(len(open_ports) * 0.1, 2.0)
        score += port_count_bonus

        return min(round(score, 2), 10.0)
