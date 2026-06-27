"""
VulnVision - Production Cybersecurity Platform
Entry point for the application.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import create_app
from backend.utils.logger import setup_logging


def main():
    """Start the VulnVision application."""
    setup_logging()
    app = create_app()

    host = app.config.get('HOST', '0.0.0.0')
    port = app.config.get('PORT', 5000)
    debug = app.config.get('DEBUG', False)

    print(f"""
    ╔══════════════════════════════════════════╗
    ║          VulnVision v1.0.0               ║
    ║   Cybersecurity Intelligence Platform    ║
    ╚══════════════════════════════════════════╝

    → Server: http://{host}:{port}
    → Mode:   {'Development' if debug else 'Production'}
    """)

    if sys.platform == 'win32':
        from waitress import serve
        serve(app, host=host, port=port)
    else:
        app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()
