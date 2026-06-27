"""
VulnVision PDF Report Generator.
Creates professional PDF vulnerability reports using reportlab.
"""
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class PDFGenerator:
    """Generates PDF vulnerability reports."""

    SEVERITY_COLORS = {
        'critical': (0.86, 0.15, 0.15),
        'high': (0.93, 0.40, 0.10),
        'medium': (0.96, 0.62, 0.04),
        'low': (0.23, 0.51, 0.96),
        'info': (0.45, 0.55, 0.65),
    }

    def generate(self, report_data, output_path):
        """Generate a PDF report.

        Args:
            report_data: Complete report data dict.
            output_path: Output file path.

        Returns:
            Output file path string.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import inch, cm
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.colors import HexColor, black, white
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                            Table, TableStyle, PageBreak)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            doc = SimpleDocTemplate(output_path, pagesize=A4,
                                    topMargin=1 * inch, bottomMargin=1 * inch,
                                    leftMargin=0.75 * inch, rightMargin=0.75 * inch)

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                         fontSize=24, spaceAfter=30,
                                         textColor=HexColor('#1a1d29'))
            heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading1'],
                                           fontSize=16, spaceAfter=12, spaceBefore=20,
                                           textColor=HexColor('#2d3148'))
            body_style = ParagraphStyle('CustomBody', parent=styles['Normal'],
                                        fontSize=10, spaceAfter=6)

            elements = []

            # Title Page
            metadata = report_data.get('metadata', {})
            elements.append(Spacer(1, 2 * inch))
            elements.append(Paragraph('VulnVision Security Report', title_style))
            elements.append(Spacer(1, 0.25 * inch))
            elements.append(Paragraph(metadata.get('report_name', 'Security Assessment'), heading_style))
            elements.append(Spacer(1, 0.5 * inch))
            elements.append(Paragraph(f"<b>Target:</b> {metadata.get('target', 'N/A')}", body_style))
            elements.append(Paragraph(f"<b>Scan Type:</b> {metadata.get('scan_type', 'N/A')}", body_style))
            elements.append(Paragraph(f"<b>Generated:</b> {metadata.get('generated_at', 'N/A')}", body_style))
            elements.append(PageBreak())

            # Executive Summary
            summary = report_data.get('summary', {})
            elements.append(Paragraph('Executive Summary', heading_style))
            elements.append(Paragraph(f"Total Hosts Discovered: {summary.get('total_hosts', 0)}", body_style))
            elements.append(Paragraph(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}", body_style))
            elements.append(Paragraph(f"Overall Risk Level: {summary.get('risk_level', 'Unknown')}", body_style))
            elements.append(Paragraph(f"Security Debt Score: {summary.get('debt_score', 0)}", body_style))

            severity_dist = summary.get('severity_distribution', {})
            if severity_dist:
                elements.append(Spacer(1, 0.25 * inch))
                elements.append(Paragraph('Severity Distribution', heading_style))
                sev_data = [['Severity', 'Count']]
                for sev in ['critical', 'high', 'medium', 'low', 'info']:
                    sev_data.append([sev.title(), str(severity_dist.get(sev, 0))])
                sev_table = Table(sev_data, colWidths=[3 * inch, 2 * inch])
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1d29')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ]))
                elements.append(sev_table)

            # Findings
            findings = report_data.get('findings', [])
            if findings:
                elements.append(PageBreak())
                elements.append(Paragraph(f'Findings ({len(findings)})', heading_style))
                table_data = [['Severity', 'Title', 'CVSS', 'Category']]
                for f in findings[:50]:
                    table_data.append([
                        f.get('severity', 'info').title(),
                        str(f.get('title', ''))[:60],
                        str(f.get('cvss_score', 0)),
                        str(f.get('category', ''))[:20],
                    ])
                findings_table = Table(table_data, colWidths=[1 * inch, 3.5 * inch, 0.75 * inch, 1.25 * inch])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1d29')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f5f5f5')]),
                ]))
                elements.append(findings_table)

            doc.build(elements)
            logger.info('PDF report generated: %s', output_path)

        except ImportError:
            logger.warning('reportlab not available, generating text fallback')
            self._generate_text_fallback(report_data, output_path)

        return output_path

    def _generate_text_fallback(self, report_data, output_path):
        """Generate a plain-text fallback when reportlab is unavailable."""
        txt_path = output_path.replace('.pdf', '.txt')
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write('VULNVISION SECURITY REPORT\n')
            f.write('=' * 60 + '\n\n')
            metadata = report_data.get('metadata', {})
            f.write(f"Report: {metadata.get('report_name', 'N/A')}\n")
            f.write(f"Target: {metadata.get('target', 'N/A')}\n")
            f.write(f"Generated: {metadata.get('generated_at', 'N/A')}\n\n")

            summary = report_data.get('summary', {})
            f.write(f"Hosts: {summary.get('total_hosts', 0)}\n")
            f.write(f"Vulnerabilities: {summary.get('total_vulnerabilities', 0)}\n")
            f.write(f"Risk Level: {summary.get('risk_level', 'Unknown')}\n\n")

            for finding in report_data.get('findings', []):
                f.write(f"[{finding.get('severity', 'info').upper()}] {finding.get('title', 'N/A')}\n")
                f.write(f"  CVSS: {finding.get('cvss_score', 0)} | Category: {finding.get('category', 'N/A')}\n\n")

        logger.info('Text fallback report generated: %s', txt_path)
        return txt_path
