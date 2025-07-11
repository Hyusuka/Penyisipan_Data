# app/app.py
import os
from flask import Flask
from app.routes import main
from app.utils.database import db_manager
from dotenv import load_dotenv

load_dotenv() 

def create_app():
    app = Flask(__name__)
    app.secret_key = 'your_secret_key'

    # Register Blueprint
    app.register_blueprint(main)

    app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER", "uploads")
    app.config['SECRET_KEY'] = 'mysecret'

    # Init DB Pool
    db_manager.init_pool()

    return app


