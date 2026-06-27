"""
VulnVision CSV Report Generator.
Creates CSV vulnerability reports for spreadsheet analysis.
"""
import csv
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class CSVGenerator:
    """Generates CSV vulnerability reports."""

    COLUMNS = [
        'Title', 'Severity', 'CVSS', 'Category', 'Host', 'Port',
        'Service', 'Status', 'Description', 'Remediation', 'Confidence', 'Detected'
    ]

    def generate(self, report_data, output_path):
        """Generate a CSV report.

        Args:
            report_data: Complete report data dict.
            output_path: Output file path.

        Returns:
            Output file path string.
        """
        findings = report_data.get('findings', [])

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(self.COLUMNS)

            for finding in findings:
                host_info = ''
                hosts = report_data.get('hosts', [])
                host_id = finding.get('host_id')
                if host_id:
                    host_record = next(
                        (h for h in hosts if h.get('id') == host_id), None
                    )
                    if host_record:
                        host_info = host_record.get('ip_address', '')

                writer.writerow([
                    finding.get('title', ''),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score', 0),
                    finding.get('category', ''),
                    host_info or finding.get('affected_service', ''),
                    finding.get('affected_port', ''),
                    finding.get('affected_service', ''),
                    finding.get('status', 'open'),
                    finding.get('description', '')[:500],
                    finding.get('remediation', '')[:500],
                    finding.get('confidence', 0),
                    finding.get('created_at', ''),
                ])

        logger.info('CSV report generated: %s (%d findings)', output_path, len(findings))
        return output_path
