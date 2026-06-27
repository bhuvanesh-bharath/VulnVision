"""
VulnVision Report Model.
Represents a generated security report with its format and storage metadata.
"""
import uuid
from datetime import datetime, timezone

from backend.models.base import db, TimestampMixin, SerializeMixin


class Report(db.Model, TimestampMixin, SerializeMixin):
    """Generated security report."""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    report_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(500), nullable=False)
    report_type = db.Column(db.String(50), nullable=False, default='technical')
    format = db.Column(db.String(20), nullable=False, default='pdf')
    file_path = db.Column(db.String(1000), nullable=True)
    file_size = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(30), nullable=False, default='pending')
    include_findings = db.Column(db.Boolean, nullable=False, default=True)
    include_attack_paths = db.Column(db.Boolean, nullable=False, default=True)
    include_remediation = db.Column(db.Boolean, nullable=False, default=True)
    include_executive_summary = db.Column(db.Boolean, nullable=False, default=True)
    generated_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    VALID_TYPES = ('executive', 'technical', 'compliance', 'full')
    VALID_FORMATS = ('pdf', 'csv', 'json')
    VALID_STATUSES = ('pending', 'generating', 'completed', 'failed')

    def __repr__(self):
        return f'<Report {self.report_id} type={self.report_type} format={self.format}>'

    def mark_generating(self):
        """Mark report as currently generating."""
        self.status = 'generating'

    def mark_completed(self, file_path, file_size):
        """Mark report as completed.

        Args:
            file_path: Path to the generated report file.
            file_size: Size of the generated file in bytes.
        """
        self.status = 'completed'
        self.file_path = file_path
        self.file_size = file_size
        self.generated_at = datetime.now(timezone.utc)

    def mark_failed(self, error_message):
        """Mark report generation as failed.

        Args:
            error_message: Description of the failure.
        """
        self.status = 'failed'
        self.error_message = error_message

    @property
    def file_size_display(self):
        """Human-readable file size.

        Returns:
            Formatted file size string.
        """
        if not self.file_size:
            return '0 B'
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'

    def to_dict(self):
        """Serialize report with display fields."""
        data = super().to_dict()
        data['file_size_display'] = self.file_size_display
        return data
