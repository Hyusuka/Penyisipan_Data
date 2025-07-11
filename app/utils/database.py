from typing import Optional, Generator
import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool, PooledMySQLConnection
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash
from app.config import Config

class DatabaseManager:
    _pool: Optional[MySQLConnectionPool] = None

    @classmethod
    def init_pool(cls) -> None:
        cls._pool = MySQLConnectionPool(
            pool_name="main_pool",
            pool_size=5,
            **Config.DATABASE_CONFIG
        )

    @contextmanager
    def get_connection(self) -> Generator[PooledMySQLConnection, None, None]:
        if self._pool is None:
            raise RuntimeError("Database pool not initialized.")
        conn = self._pool.get_connection()
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS log_proses (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        tipe VARCHAR(50) NOT NULL,
                        nama_file VARCHAR(255) NOT NULL,
                        waktu DATETIME NOT NULL,
                        status TEXT NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS password (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        file_name VARCHAR(255) NOT NULL,
                        key_hash VARCHAR(255) NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE (file_name)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                conn.commit()

db_manager = DatabaseManager()
