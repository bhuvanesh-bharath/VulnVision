"""
VulnVision Database Base.
SQLAlchemy instance and base model mixin.
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()


class TimestampMixin:
    """Mixin that adds created_at and updated_at columns to models."""
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )


class SerializeMixin:
    """Mixin that provides dictionary serialization for models."""

    _serialize_fields = None
    _exclude_fields = None

    def to_dict(self):
        """Serialize model instance to dictionary.

        Returns:
            Dictionary representation of the model.
        """
        result = {}
        columns = self._serialize_fields or [c.name for c in self.__table__.columns]
        exclude = self._exclude_fields or []

        for col_name in columns:
            if col_name in exclude:
                continue
            value = getattr(self, col_name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[col_name] = value
        return result

    @classmethod
    def from_dict(cls, data):
        """Create a model instance from a dictionary.

        Args:
            data: Dictionary with model field values.

        Returns:
            Model instance.
        """
        columns = {c.name for c in cls.__table__.columns}
        filtered = {k: v for k, v in data.items() if k in columns}
        return cls(**filtered)
