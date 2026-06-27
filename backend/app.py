"""
VulnVision Flask Application Factory.
Creates and configures the Flask application with all extensions and blueprints.
"""
import os
from flask import Flask
from flask_cors import CORS

from backend.config import get_config, Config
from backend.models.base import db
from backend.middleware.error_handler import register_error_handlers
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def create_app(config_class=None):
    """Create and configure the Flask application.

    Args:
        config_class: Configuration class to use. If None, determined by environment.

    Returns:
        Configured Flask application instance.
    """
    if config_class is None:
        config_class = get_config()

    Config.init_dirs()

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'templates'),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'static')
    )
    app.config.from_object(config_class)

    _init_extensions(app)
    _register_blueprints(app)
    register_error_handlers(app)
    _init_database(app)

    logger.info('VulnVision application initialized successfully')

    return app


def _init_extensions(app):
    """Initialize Flask extensions."""
    db.init_app(app)
    CORS(app)


def _register_blueprints(app):
    """Register all API blueprints."""
    from backend.api.dashboard import dashboard_bp
    from backend.api.scans import scans_bp
    from backend.api.hosts import hosts_bp
    from backend.api.vulnerabilities import vulnerabilities_bp
    from backend.api.attack_paths import attack_paths_bp
    from backend.api.security_debt import security_debt_bp
    from backend.api.reports import reports_bp
    from backend.api.remediation import remediation_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp, url_prefix='/api/scans')
    app.register_blueprint(hosts_bp, url_prefix='/api/hosts')
    app.register_blueprint(vulnerabilities_bp, url_prefix='/api/vulnerabilities')
    app.register_blueprint(attack_paths_bp, url_prefix='/api/attack-paths')
    app.register_blueprint(security_debt_bp, url_prefix='/api/security-debt')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(remediation_bp, url_prefix='/api/remediation')


def _init_database(app):
    """Initialize database and create tables."""
    with app.app_context():
        import backend.models.scan
        import backend.models.host
        import backend.models.port
        import backend.models.vulnerability
        import backend.models.attack_path
        import backend.models.security_debt
        import backend.models.report
        import backend.models.audit_log
        db.create_all()
        logger.info('Database tables initialized')
