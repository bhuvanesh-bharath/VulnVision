"""
VulnVision Configuration Module.
Centralized configuration for all application settings.
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    """Base configuration."""

    # Application
    APP_NAME = 'VulnVision'
    APP_VERSION = '1.0.0'
    SECRET_KEY = os.environ.get('VULNVISION_SECRET_KEY', 'vulnvision-dev-key-change-in-production')
    DEBUG = False
    TESTING = False
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('VULNVISION_PORT', 5000))

    # Database
    DATABASE_DIR = os.path.join(BASE_DIR, 'database')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(DATABASE_DIR, "vulnvision.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # Logging
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    # Exports
    EXPORT_DIR = os.path.join(BASE_DIR, 'exports')

    # Scanner Settings
    SCANNER_MAX_THREADS = int(os.environ.get('SCANNER_MAX_THREADS', 50))
    SCANNER_TIMEOUT = int(os.environ.get('SCANNER_TIMEOUT', 5))
    SCANNER_DEFAULT_PORTS = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443'
    SCANNER_FULL_PORT_RANGE = '1-65535'

    # Vulnerability Detection
    VULN_CONFIDENCE_THRESHOLD = 0.3
    VULN_SEVERITY_WEIGHTS = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5,
        'info': 0.5
    }

    # Attack Path
    ATTACK_PATH_MAX_DEPTH = 5
    ATTACK_PATH_MIN_CONFIDENCE = 0.2

    # Security Debt
    DEBT_DECAY_FACTOR = 0.95
    DEBT_MAX_HISTORY = 90

    # Report Settings
    REPORT_COMPANY_NAME = os.environ.get('REPORT_COMPANY', 'VulnVision Security')
    REPORT_MAX_FINDINGS_PER_PAGE = 50

    @staticmethod
    def init_dirs():
        """Ensure required directories exist."""
        dirs = [
            Config.DATABASE_DIR,
            Config.LOG_DIR,
            Config.EXPORT_DIR,
            os.path.join(Config.EXPORT_DIR, 'pdf'),
            os.path.join(Config.EXPORT_DIR, 'csv'),
            os.path.join(Config.EXPORT_DIR, 'json'),
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    LOG_LEVEL = 'WARNING'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    LOG_LEVEL = 'DEBUG'


config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment."""
    env = os.environ.get('VULNVISION_ENV', 'development').lower()
    return config_map.get(env, DevelopmentConfig)
