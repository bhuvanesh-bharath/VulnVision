"""
VulnVision Database Initialization.
Creates database schema and seeds initial data.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.models.base import db
from backend.utils.logger import setup_logging, get_logger

logger = get_logger(__name__)


def init_database():
    """Initialize the database, creating all tables."""
    setup_logging()
    app = create_app()

    with app.app_context():
        db.create_all()
        logger.info('Database tables created successfully')
        print('Database initialized successfully.')
        print(f'Database location: {app.config["SQLALCHEMY_DATABASE_URI"]}')


def reset_database():
    """Drop all tables and recreate them. USE WITH CAUTION."""
    setup_logging()
    app = create_app()

    with app.app_context():
        db.drop_all()
        logger.info('All database tables dropped')
        db.create_all()
        logger.info('Database tables recreated')
        print('Database reset completed.')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--reset':
        confirm = input('This will DELETE ALL DATA. Type "yes" to confirm: ')
        if confirm.lower() == 'yes':
            reset_database()
        else:
            print('Reset cancelled.')
    else:
        init_database()
