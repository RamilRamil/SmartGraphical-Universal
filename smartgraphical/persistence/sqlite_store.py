"""SQLite connection factory with idempotent schema bootstrap.

Design notes:
- A single instance encapsulates one database file path.
- Every acquired connection has foreign_keys=ON and row_factory=Row.
- open() is a context manager that always closes the connection.
- Schema is applied on init; script is idempotent.
"""
import os
import sqlite3
import threading
from contextlib import contextmanager


SCHEMA_FILENAME = "schema.sql"


class SqliteStore:

    def __init__(self, database_path):
        if not database_path:
            raise ValueError("database_path must be non-empty")
        self._database_path = database_path
        self._lock = threading.Lock()
        self._ensure_parent_directory()
        self._apply_schema()

    @property
    def database_path(self):
        return self._database_path

    def connect(self):
        connection = sqlite3.connect(self._database_path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON;")
        return connection

    @contextmanager
    def open(self):
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    def _ensure_parent_directory(self):
        parent = os.path.dirname(os.path.abspath(self._database_path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _apply_schema(self):
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), SCHEMA_FILENAME)
        if not os.path.isfile(schema_path):
            raise RuntimeError(f"schema file not found: {schema_path}")
        with open(schema_path, "r", encoding="utf-8") as handle:
            script = handle.read()
        with self._lock, self.open() as connection:
            connection.executescript(script)
