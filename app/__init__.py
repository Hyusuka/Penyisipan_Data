# app/__init__.py
import os
from flask import Flask
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecret')
    app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')


    # Register Blueprints
    from app.routes import main
    app.register_blueprint(main)
        
    return app


