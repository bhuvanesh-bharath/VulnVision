"""
VulnVision Security Debt Engine.
Calculates a composite security debt score from vulnerability, legacy service, exposure, and configuration components.
"""
import json
from datetime import datetime, timezone
from backend.models.base import db
from backend.models.host import Host
from backend.models.port import Port
from backend.models.vulnerability import Vulnerability
from backend.models.security_debt import SecurityDebt
from backend.utils.logger import get_scan_logger

logger = get_scan_logger()


class SecurityDebtEngine:
    """Calculates and tracks security debt over time."""

    LEGACY_SERVICES = {'telnet', 'ftp', 'tftp', 'snmp', 'rsh', 'rlogin', 'finger'}
    SEVERITY_DEBT_WEIGHTS = {'critical': 10.0, 'high': 6.0, 'medium': 3.0, 'low': 1.0, 'info': 0.2}
    COMPONENT_WEIGHTS = {
        'vulnerability_debt': 0.40,
        'legacy_service_debt': 0.20,
        'exposure_debt': 0.25,
        'configuration_debt': 0.15
    }

    def calculate(self, scan_id):
        """Calculate security debt for a completed scan.

        Args:
            scan_id: Database ID of the scan.

        Returns:
            Created SecurityDebt model instance.
        """
        hosts = Host.query.filter_by(scan_id=scan_id).all()
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()

        all_ports = []
        for host in hosts:
            ports = Port.query.filter_by(host_id=host.id).all()
            all_ports.extend(ports)

        vuln_debt = self._calculate_vulnerability_debt(vulns)
        legacy_debt = self._calculate_legacy_service_debt(hosts, all_ports)
        exposure_debt = self._calculate_exposure_debt(hosts, all_ports)
        config_debt = self._calculate_configuration_debt(vulns)

        components = {
            'vulnerability_debt': vuln_debt,
            'legacy_service_debt': legacy_debt,
            'exposure_debt': exposure_debt,
            'configuration_debt': config_debt,
        }
        total = self._calculate_total_debt(components)
        trend_direction, trend_change = self._determine_trend(total, scan_id)
        recommendations = self._generate_recommendations(components)

        try:
            debt = SecurityDebt(
                scan_id=scan_id,
                debt_score=round(total, 2),
                vulnerability_debt=round(vuln_debt, 2),
                legacy_service_debt=round(legacy_debt, 2),
                exposure_debt=round(exposure_debt, 2),
                configuration_debt=round(config_debt, 2),
                trend=trend_direction,
                trend_percentage=round(trend_change, 2),
                recommendations=recommendations,
                calculated_at=datetime.now(timezone.utc),
            )
            db.session.add(debt)
            db.session.commit()
            logger.info('Security debt calculated for scan %d: score=%.2f trend=%s',
                        scan_id, total, trend_direction)
            return debt
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to persist security debt: %s', str(e))
            raise

    def _calculate_vulnerability_debt(self, vulnerabilities):
        """Calculate debt from unresolved vulnerabilities.

        Args:
            vulnerabilities: List of Vulnerability instances.

        Returns:
            Float debt score 0-100.
        """
        if not vulnerabilities:
            return 0.0

        total = 0.0
        for v in vulnerabilities:
            weight = self.SEVERITY_DEBT_WEIGHTS.get(v.severity, 1.0)
            status_multiplier = 1.0 if v.status == 'open' else 0.3
            total += weight * status_multiplier

        max_possible = len(vulnerabilities) * 10.0
        return min(100.0, (total / max_possible) * 100) if max_possible > 0 else 0.0

    def _calculate_legacy_service_debt(self, hosts, ports):
        """Calculate debt from legacy/deprecated services.

        Args:
            hosts: List of Host instances.
            ports: List of Port instances.

        Returns:
            Float debt score 0-100.
        """
        if not ports:
            return 0.0

        legacy_count = sum(
            1 for p in ports
            if p.service_name and p.service_name.lower() in self.LEGACY_SERVICES
        )

        old_ssh = sum(
            1 for p in ports
            if p.service_name == 'ssh' and p.service_version
            and any(v in p.service_version.lower() for v in ['1.', 'v1', 'ssh-1'])
        )

        total_legacy = legacy_count + old_ssh
        total_services = max(len(ports), 1)

        return min(100.0, (total_legacy / total_services) * 100 * 5)

    def _calculate_exposure_debt(self, hosts, ports):
        """Calculate debt from network exposure.

        Args:
            hosts: List of Host instances.
            ports: List of Port instances.

        Returns:
            Float debt score 0-100.
        """
        if not hosts:
            return 0.0

        total_open = sum(1 for p in ports if p.state == 'open')
        high_risk_open = sum(
            1 for p in ports
            if p.state == 'open' and p.port_number in (21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017, 161)
        )

        host_count = max(len(hosts), 1)
        avg_open = total_open / host_count
        exposure = min(100.0, (avg_open / 20) * 60 + (high_risk_open / max(total_open, 1)) * 40)

        return exposure

    def _calculate_configuration_debt(self, vulnerabilities):
        """Calculate debt from configuration issues.

        Args:
            vulnerabilities: List of Vulnerability instances.

        Returns:
            Float debt score 0-100.
        """
        config_categories = {'missing_headers', 'information_disclosure', 'admin_panel', 'insecure_protocol'}
        config_vulns = [v for v in vulnerabilities if v.category in config_categories]

        if not config_vulns:
            return 0.0

        total_weight = sum(self.SEVERITY_DEBT_WEIGHTS.get(v.severity, 1.0) for v in config_vulns)
        max_possible = len(config_vulns) * 10.0

        return min(100.0, (total_weight / max_possible) * 100) if max_possible > 0 else 0.0

    def _calculate_total_debt(self, components):
        """Calculate weighted total debt score.

        Args:
            components: Dict of component name to score.

        Returns:
            Float total debt score 0-100.
        """
        total = sum(
            components.get(name, 0) * weight
            for name, weight in self.COMPONENT_WEIGHTS.items()
        )
        return min(100.0, total)

    def _determine_trend(self, current_score, scan_id):
        """Determine debt trend compared to previous scans.

        Args:
            current_score: Current total debt score.
            scan_id: Current scan ID.

        Returns:
            Tuple of (direction_str, change_float).
        """
        previous = SecurityDebt.query.filter(
            SecurityDebt.scan_id != scan_id
        ).order_by(SecurityDebt.calculated_at.desc()).first()

        if not previous:
            return 'stable', 0.0

        change = current_score - previous.debt_score
        if change > 2:
            return 'increasing', change
        elif change < -2:
            return 'decreasing', change
        else:
            return 'stable', change

    def _generate_recommendations(self, components):
        """Generate prioritized recommendations based on debt components.

        Args:
            components: Dict of component scores.

        Returns:
            List of recommendation dicts.
        """
        recommendations = []

        sorted_components = sorted(components.items(), key=lambda x: x[1], reverse=True)

        for name, score in sorted_components:
            if score <= 5:
                continue

            if name == 'vulnerability_debt':
                recommendations.append({
                    'priority': 1 if score > 50 else 2,
                    'category': 'vulnerability_remediation',
                    'title': 'Address Outstanding Vulnerabilities',
                    'description': f'Vulnerability debt is at {score:.0f}%. Prioritize critical and high-severity findings.',
                    'impact': 'high' if score > 50 else 'medium',
                })
            elif name == 'legacy_service_debt':
                recommendations.append({
                    'priority': 2 if score > 50 else 3,
                    'category': 'service_modernization',
                    'title': 'Modernize Legacy Services',
                    'description': f'Legacy service debt is at {score:.0f}%. Replace Telnet with SSH, FTP with SFTP.',
                    'impact': 'high' if score > 50 else 'medium',
                })
            elif name == 'exposure_debt':
                recommendations.append({
                    'priority': 1 if score > 60 else 2,
                    'category': 'network_hardening',
                    'title': 'Reduce Network Exposure',
                    'description': f'Exposure debt is at {score:.0f}%. Close unnecessary ports, implement firewalls.',
                    'impact': 'high' if score > 60 else 'medium',
                })
            elif name == 'configuration_debt':
                recommendations.append({
                    'priority': 3,
                    'category': 'configuration_hardening',
                    'title': 'Improve Security Configuration',
                    'description': f'Configuration debt is at {score:.0f}%. Add security headers, remove info disclosure.',
                    'impact': 'medium',
                })

        return sorted(recommendations, key=lambda r: r['priority'])
