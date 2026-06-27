"""
VulnVision Base Repository.
Generic repository pattern implementation for common CRUD operations.
"""
from backend.models.base import db
from backend.utils.logger import get_logger
from backend.utils.exceptions import NotFoundError, DatabaseError

logger = get_logger(__name__)


class BaseRepository:
    """Base repository providing common CRUD operations.

    Attributes:
        model: SQLAlchemy model class this repository manages.
    """

    model = None

    @classmethod
    def get_by_id(cls, record_id):
        """Get a record by its primary key ID.

        Args:
            record_id: Primary key value.

        Returns:
            Model instance.

        Raises:
            NotFoundError: If record is not found.
        """
        record = db.session.get(cls.model, record_id)
        if not record:
            raise NotFoundError(cls.model.__name__, record_id)
        return record

    @classmethod
    def get_all(cls, page=None, per_page=None, order_by=None):
        """Get all records with optional pagination.

        Args:
            page: Page number (1-indexed).
            per_page: Records per page.
            order_by: Column to order by.

        Returns:
            List of model instances or pagination object.
        """
        query = cls.model.query
        if order_by is not None:
            query = query.order_by(order_by)
        if page and per_page:
            return query.paginate(page=page, per_page=per_page, error_out=False)
        return query.all()

    @classmethod
    def create(cls, **kwargs):
        """Create a new record.

        Args:
            **kwargs: Field values for the new record.

        Returns:
            Created model instance.

        Raises:
            DatabaseError: If creation fails.
        """
        try:
            record = cls.model(**kwargs)
            db.session.add(record)
            db.session.commit()
            logger.debug('Created %s with id=%s', cls.model.__name__, record.id)
            return record
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to create %s: %s', cls.model.__name__, str(e))
            raise DatabaseError(f'Failed to create {cls.model.__name__}: {str(e)}')

    @classmethod
    def update(cls, record_id, **kwargs):
        """Update an existing record.

        Args:
            record_id: Primary key of the record to update.
            **kwargs: Fields to update.

        Returns:
            Updated model instance.

        Raises:
            NotFoundError: If record is not found.
            DatabaseError: If update fails.
        """
        try:
            record = cls.get_by_id(record_id)
            for key, value in kwargs.items():
                if hasattr(record, key):
                    setattr(record, key, value)
            db.session.commit()
            logger.debug('Updated %s id=%s', cls.model.__name__, record_id)
            return record
        except NotFoundError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to update %s id=%s: %s', cls.model.__name__, record_id, str(e))
            raise DatabaseError(f'Failed to update {cls.model.__name__}: {str(e)}')

    @classmethod
    def delete(cls, record_id):
        """Delete a record by ID.

        Args:
            record_id: Primary key of the record to delete.

        Raises:
            NotFoundError: If record is not found.
            DatabaseError: If deletion fails.
        """
        try:
            record = cls.get_by_id(record_id)
            db.session.delete(record)
            db.session.commit()
            logger.debug('Deleted %s id=%s', cls.model.__name__, record_id)
        except NotFoundError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to delete %s id=%s: %s', cls.model.__name__, record_id, str(e))
            raise DatabaseError(f'Failed to delete {cls.model.__name__}: {str(e)}')

    @classmethod
    def count(cls):
        """Get total count of records.

        Returns:
            Integer count.
        """
        return cls.model.query.count()

    @classmethod
    def exists(cls, record_id):
        """Check if a record exists.

        Args:
            record_id: Primary key to check.

        Returns:
            Boolean indicating existence.
        """
        return db.session.get(cls.model, record_id) is not None

    @classmethod
    def bulk_create(cls, records_data):
        """Create multiple records in a single transaction.

        Args:
            records_data: List of dictionaries with field values.

        Returns:
            List of created model instances.

        Raises:
            DatabaseError: If bulk creation fails.
        """
        try:
            records = [cls.model(**data) for data in records_data]
            db.session.add_all(records)
            db.session.commit()
            logger.debug('Bulk created %d %s records', len(records), cls.model.__name__)
            return records
        except Exception as e:
            db.session.rollback()
            logger.error('Failed to bulk create %s: %s', cls.model.__name__, str(e))
            raise DatabaseError(f'Failed to bulk create {cls.model.__name__}: {str(e)}')
