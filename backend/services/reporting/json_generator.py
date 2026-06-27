"""
VulnVision JSON Report Generator.
Creates structured JSON vulnerability reports.
"""
import json
from datetime import datetime, timezone
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class JSONReportGenerator:
    """Generates JSON vulnerability reports."""

    def generate(self, report_data, output_path):
        """Generate a JSON report.

        Args:
            report_data: Complete report data dict.
            output_path: Output file path.

        Returns:
            Output file path string.
        """
        output = {
            'report_format': 'VulnVision JSON Report v1.0',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'metadata': report_data.get('metadata', {}),
            'executive_summary': report_data.get('summary', {}),
            'hosts': report_data.get('hosts', []),
            'findings': report_data.get('findings', []),
            'attack_paths': report_data.get('attack_paths', []),
            'remediation': report_data.get('remediation', []),
            'security_debt': report_data.get('security_debt'),
            'statistics': {
                'total_hosts': len(report_data.get('hosts', [])),
                'total_findings': len(report_data.get('findings', [])),
                'total_attack_paths': len(report_data.get('attack_paths', [])),
            }
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, default=str)

        logger.info('JSON report generated: %s', output_path)
        return output_path
