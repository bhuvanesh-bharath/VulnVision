"""
VulnVision Report Generator.
Orchestrates report generation across multiple formats (PDF, CSV, JSON).
"""
import os
from datetime import datetime, timezone
from backend.models.base import db
from backend.models.report import Report
from backend.models.scan import Scan
from backend.models.host import Host
from backend.models.vulnerability import Vulnerability
from backend.models.attack_path import AttackPath
from backend.models.security_debt import SecurityDebt
from backend.services.reporting.pdf_generator import PDFGenerator
from backend.services.reporting.csv_generator import CSVGenerator
from backend.services.reporting.json_generator import JSONReportGenerator
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Orchestrates report generation in multiple formats."""

    FORMAT_GENERATORS = {
        'pdf': PDFGenerator,
        'csv': CSVGenerator,
        'json': JSONReportGenerator,
    }

    def __init__(self):
        self.exports_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )), 'exports')
        os.makedirs(self.exports_dir, exist_ok=True)

    def generate(self, report_id):
        """Generate a report file.

        Args:
            report_id: Database ID of the Report record.

        Returns:
            String file path of generated report.
        """
        report = db.session.get(Report, report_id)
        if not report:
            raise ValueError(f'Report with ID {report_id} not found')

        scan = db.session.get(Scan, report.scan_id)
        if not scan:
            raise ValueError(f'Scan with ID {report.scan_id} not found')

        report.mark_generating()
        db.session.commit()

        try:
            report_data = self._build_report_data(scan, report)

            fmt = report.format or 'json'
            generator_cls = self.FORMAT_GENERATORS.get(fmt, JSONReportGenerator)
            generator = generator_cls()

            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            safe_name = ''.join(c if c.isalnum() or c in '-_' else '_' for c in (report.name or 'report'))
            filename = f'{safe_name}_{timestamp}.{fmt}'
            output_path = os.path.join(self.exports_dir, filename)

            generator.generate(report_data, output_path)

            file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
            report.mark_completed(output_path, file_size)
            db.session.commit()

            logger.info('Report generated: %s (%d bytes)', output_path, file_size)
            return output_path

        except Exception as e:
            report.mark_failed(str(e))
            db.session.commit()
            logger.error('Report generation failed: %s', str(e))
            raise

    def _build_report_data(self, scan, report):
        """Build the complete report data dictionary.

        Args:
            scan: Scan model instance.
            report: Report model instance.

        Returns:
            Dict with all report sections.
        """
        hosts = Host.query.filter_by(scan_id=scan.id).all()
        vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
        paths = AttackPath.query.filter_by(scan_id=scan.id).all()
        debt = SecurityDebt.query.filter_by(scan_id=scan.id).first()

        data = {
            'metadata': {
                'report_name': report.name,
                'report_type': report.report_type,
                'format': report.format,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'scan_id': scan.scan_id,
                'scan_name': scan.name,
                'target': scan.target,
                'scan_type': scan.scan_type,
                'scan_status': scan.status,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            },
            'summary': self._build_executive_summary(scan, vulns, debt),
            'hosts': [h.to_dict() for h in hosts],
            'findings': self._build_findings_section(vulns),
            'attack_paths': self._build_attack_path_section(paths),
            'remediation': self._build_remediation_section(vulns),
            'security_debt': debt.to_dict() if debt else None,
        }

        return data

    def _build_executive_summary(self, scan, vulns, debt):
        """Build executive summary section.

        Args:
            scan: Scan model instance.
            vulns: List of Vulnerability instances.
            debt: SecurityDebt instance or None.

        Returns:
            Dict with summary data.
        """
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vulns:
            if v.severity in severity_counts:
                severity_counts[v.severity] += 1

        return {
            'total_hosts': scan.hosts_discovered or 0,
            'total_vulnerabilities': len(vulns),
            'severity_distribution': severity_counts,
            'debt_score': debt.debt_score if debt else 0,
            'risk_level': 'Critical' if severity_counts['critical'] > 0
                          else 'High' if severity_counts['high'] > 0
                          else 'Medium' if severity_counts['medium'] > 0
                          else 'Low',
        }

    def _build_findings_section(self, vulns):
        """Build findings section.

        Args:
            vulns: List of Vulnerability instances.

        Returns:
            List of finding dicts.
        """
        return [v.to_dict() for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True)]

    def _build_attack_path_section(self, paths):
        """Build attack paths section.

        Args:
            paths: List of AttackPath instances.

        Returns:
            List of attack path dicts.
        """
        return [p.to_dict() for p in sorted(paths, key=lambda x: x.risk_score, reverse=True)]

    def _build_remediation_section(self, vulns):
        """Build remediation section.

        Args:
            vulns: List of Vulnerability instances.

        Returns:
            List of remediation dicts.
        """
        recs = []
        for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True):
            if v.remediation:
                recs.append({
                    'title': v.title,
                    'severity': v.severity,
                    'remediation': v.remediation,
                    'cvss_score': v.cvss_score,
                })
        return recs
