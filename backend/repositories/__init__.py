"""
VulnVision Repositories Package.
Data access layer for all database operations.
"""
from backend.repositories.scan_repository import ScanRepository
from backend.repositories.host_repository import HostRepository
from backend.repositories.port_repository import PortRepository
from backend.repositories.vulnerability_repository import VulnerabilityRepository
from backend.repositories.attack_path_repository import AttackPathRepository
from backend.repositories.security_debt_repository import SecurityDebtRepository
from backend.repositories.report_repository import ReportRepository
from backend.repositories.audit_log_repository import AuditLogRepository

__all__ = [
    'ScanRepository', 'HostRepository', 'PortRepository',
    'VulnerabilityRepository', 'AttackPathRepository',
    'SecurityDebtRepository', 'ReportRepository', 'AuditLogRepository'
]
