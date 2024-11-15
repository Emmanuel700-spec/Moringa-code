from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db = SQLAlchemy()  # Initialize db here
jwt = JWTManager()  # Initialize JWTManager

def create_app(config_object):
    app = Flask(__name__)
    app.config.from_object(config_object)
    
    db.init_app(app)  # Initialize db with the app
    jwt.init_app(app)  # Initialize JWT with the app
    
    # Register Blueprints (routes)
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    return app
