"""
VulnVision Error Handler Middleware.
Centralized error handling for all API endpoints.
"""
from flask import jsonify, request
from backend.utils.exceptions import VulnVisionError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def register_error_handlers(app):
    """Register all error handlers with the Flask application.

    Args:
        app: Flask application instance.
    """

    @app.errorhandler(VulnVisionError)
    def handle_vulnvision_error(error):
        """Handle custom VulnVision exceptions."""
        logger.error(
            'VulnVisionError: %s | Status: %d | Path: %s',
            error.message, error.status_code, request.path
        )
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors."""
        logger.warning('Bad Request: %s | Path: %s', str(error), request.path)
        return jsonify({
            'error': True,
            'message': 'Bad request',
            'status_code': 400,
            'details': {}
        }), 400

    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 Not Found errors."""
        logger.info('Not Found: %s', request.path)
        return jsonify({
            'error': True,
            'message': f'Resource not found: {request.path}',
            'status_code': 404,
            'details': {}
        }), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        logger.warning('Method Not Allowed: %s %s', request.method, request.path)
        return jsonify({
            'error': True,
            'message': f'Method {request.method} not allowed for {request.path}',
            'status_code': 405,
            'details': {}
        }), 405

    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle 500 Internal Server Error."""
        logger.error('Internal Server Error: %s | Path: %s', str(error), request.path)
        return jsonify({
            'error': True,
            'message': 'Internal server error',
            'status_code': 500,
            'details': {}
        }), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Catch-all handler for unhandled exceptions."""
        logger.exception('Unhandled Exception: %s | Path: %s', str(error), request.path)
        return jsonify({
            'error': True,
            'message': 'An unexpected error occurred',
            'status_code': 500,
            'details': {'type': type(error).__name__}
        }), 500

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        return response
