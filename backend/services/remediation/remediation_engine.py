"""
VulnVision Remediation Engine.
Generates prioritized remediation recommendations for discovered vulnerabilities.
"""
from backend.models.vulnerability import Vulnerability
from backend.utils.logger import get_scan_logger

logger = get_scan_logger()


CATEGORY_REMEDIATION = {
    'network_exposure': {
        'fix': 'Implement network segmentation and firewall rules to restrict access.',
        'steps': [
            'Identify all unnecessary exposed services',
            'Create firewall rules to block external access to internal services',
            'Implement network segmentation using VLANs',
            'Deploy an intrusion detection/prevention system (IDS/IPS)',
            'Verify rules with a follow-up scan',
        ],
    },
    'weak_service': {
        'fix': 'Upgrade, patch, or disable weak services.',
        'steps': [
            'Identify the current version of the affected service',
            'Check for available security patches or upgrades',
            'Test the upgrade in a staging environment',
            'Apply the patch/upgrade during a maintenance window',
            'Verify the service is running the updated version',
        ],
    },
    'missing_headers': {
        'fix': 'Add missing HTTP security headers to web server configuration.',
        'steps': [
            'Identify the web server type (Apache, Nginx, IIS)',
            'Add the missing security headers to the server configuration',
            'For Apache: Add headers in .htaccess or httpd.conf',
            'For Nginx: Add headers in the server block',
            'Test with a security header scanning tool',
        ],
    },
    'insecure_protocol': {
        'fix': 'Migrate to secure protocol alternatives.',
        'steps': [
            'Identify all services using the insecure protocol',
            'Plan migration to the secure alternative (e.g., SSH instead of Telnet)',
            'Deploy the secure alternative and test connectivity',
            'Update client configurations to use the new protocol',
            'Disable the insecure protocol after migration is verified',
        ],
    },
    'admin_panel': {
        'fix': 'Restrict access to administrative interfaces.',
        'steps': [
            'Implement IP-based allowlists for admin panels',
            'Require VPN access for remote administration',
            'Enable multi-factor authentication (MFA)',
            'Remove admin panels from public-facing servers if possible',
            'Monitor admin panel access logs for anomalies',
        ],
    },
    'information_disclosure': {
        'fix': 'Remove or obfuscate information-leaking headers and responses.',
        'steps': [
            'Remove Server header or configure it to a generic value',
            'Remove X-Powered-By header from responses',
            'Disable directory listing on web servers',
            'Ensure error pages do not reveal stack traces or system info',
            'Review all HTTP response headers for unnecessary information',
        ],
    },
    'deprecated_service': {
        'fix': 'Create a decommission plan for deprecated services.',
        'steps': [
            'Inventory all systems using the deprecated service',
            'Identify modern alternatives and plan migration',
            'Communicate timeline to stakeholders',
            'Execute migration in phases with rollback plans',
            'Decommission the deprecated service after validation',
        ],
    },
}

EFFORT_MAP = {
    ('critical', 'network_exposure'): 'high',
    ('critical', 'weak_service'): 'high',
    ('high', 'network_exposure'): 'medium',
    ('high', 'missing_headers'): 'low',
    ('medium', 'missing_headers'): 'low',
    ('low', 'missing_headers'): 'low',
    ('low', 'information_disclosure'): 'low',
}


class RemediationEngine:
    """Generates prioritized remediation plans for scan findings."""

    def generate(self, scan_id):
        """Generate remediation recommendations for all vulnerabilities in a scan.

        Args:
            scan_id: Database ID of the scan.

        Returns:
            List of remediation recommendation dicts.
        """
        vulns = Vulnerability.query.filter_by(scan_id=scan_id, status='open').order_by(
            Vulnerability.cvss_score.desc()
        ).all()

        if not vulns:
            return []

        recommendations = []
        for vuln in vulns:
            rec = self._generate_recommendations(vuln)
            recommendations.append(rec)

        recommendations.sort(key=lambda r: r['priority'])
        logger.info('Generated %d remediation recommendations for scan %d', len(recommendations), scan_id)
        return recommendations

    def _generate_recommendations(self, vulnerability):
        """Generate a remediation recommendation for a single vulnerability.

        Args:
            vulnerability: Vulnerability model instance.

        Returns:
            Dict with fix, priority, risk_reduction, mitigation_steps, effort_estimate.
        """
        category = vulnerability.category or 'general'
        cat_remediation = self._get_remediation_for_category(category, vulnerability)

        return {
            'vulnerability_id': vulnerability.id,
            'vuln_id': vulnerability.vuln_id,
            'title': vulnerability.title,
            'severity': vulnerability.severity,
            'category': category,
            'host_ip': vulnerability.affected_service,
            'port': vulnerability.affected_port,
            'fix': cat_remediation.get('fix', vulnerability.remediation or 'Review and remediate.'),
            'priority': self._calculate_priority(vulnerability),
            'risk_reduction': self._estimate_risk_reduction(vulnerability),
            'mitigation_steps': cat_remediation.get('steps', self._generate_mitigation_steps(category, vulnerability)),
            'effort_estimate': self._estimate_effort(category, vulnerability.severity),
            'cvss_score': vulnerability.cvss_score,
        }

    def _get_remediation_for_category(self, category, vuln):
        """Get category-specific remediation guidance.

        Args:
            category: Vulnerability category string.
            vuln: Vulnerability instance.

        Returns:
            Dict with fix and steps.
        """
        if category in CATEGORY_REMEDIATION:
            return CATEGORY_REMEDIATION[category]

        return {
            'fix': vuln.remediation or 'Investigate and remediate according to security best practices.',
            'steps': self._generate_mitigation_steps(category, vuln),
        }

    def _calculate_priority(self, vulnerability):
        """Calculate remediation priority (1=highest, 5=lowest).

        Args:
            vulnerability: Vulnerability instance.

        Returns:
            Integer priority 1-5.
        """
        severity_priority = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        return severity_priority.get(vulnerability.severity, 3)

    def _estimate_risk_reduction(self, vulnerability):
        """Estimate the percentage of risk reduction from remediation.

        Args:
            vulnerability: Vulnerability instance.

        Returns:
            Float percentage 0-100.
        """
        base = {'critical': 90, 'high': 75, 'medium': 50, 'low': 25, 'info': 10}
        return base.get(vulnerability.severity, 30)

    def _estimate_effort(self, category, severity):
        """Estimate remediation effort level.

        Args:
            category: Vulnerability category.
            severity: Vulnerability severity.

        Returns:
            String effort level: 'low', 'medium', or 'high'.
        """
        key = (severity, category)
        if key in EFFORT_MAP:
            return EFFORT_MAP[key]

        if severity in ('critical', 'high'):
            return 'high'
        elif severity == 'medium':
            return 'medium'
        return 'low'

    def _generate_mitigation_steps(self, category, vuln):
        """Generate generic mitigation steps when no category template exists.

        Args:
            category: Vulnerability category.
            vuln: Vulnerability instance.

        Returns:
            List of mitigation step strings.
        """
        return [
            f'Assess the impact of {vuln.title} on your environment',
            'Develop a remediation plan with appropriate stakeholders',
            'Test the fix in a staging environment before production deployment',
            'Apply the fix during an approved maintenance window',
            'Verify the vulnerability is resolved with a follow-up scan',
        ]
