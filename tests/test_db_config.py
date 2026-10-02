# tests/test_db_config.py
import pytest
from app.core.database import engine

@pytest.mark.postgres
def test_database_name_ends_with_test():
    # engine.url.database gives the database name
    assert engine.url.database.endswith("_test")