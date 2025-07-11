import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'ftte vrxc wehh jshd'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

class Config:
    SECRET_KEY = 'mysecret'
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    DATABASE_CONFIG = {
        'host': 'localhost',
        'user': 'root',
        'password': '',
        'database': 'kripto_stego',
        'charset': 'utf8mb4',
        'use_pure': True,
        'port': 3306
    }
    
    @staticmethod
    def init_app(app):
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
