from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from auth.models import db
from auth.config import Config
from auth.routes import auth_bp
from flask_cors import CORS

# Create a global app instance
app = Flask(__name__)

# Load the configuration from the Config class
app.config.from_object(Config)

CORS(app, origins=["http://localhost:3000"], allow_headers=["Content-Type", "Authorization"])


# Initialize JWTManager for token handling
jwt = JWTManager(app)

# Initialize Migrate for database migrations
migrate = Migrate(app, db)

# Register Blueprints for routes
app.register_blueprint(auth_bp, url_prefix='/api/auth')  # Ensure proper URL prefix

# Initialize the database
db.init_app(app)


with app.app_context():
    db.create_all()

def create_app():
    """Function to configure and return the Flask app instance."""
    return app

if __name__ == '__main__':
    app = create_app()  # Calling the create_app function
    app.run(debug=True)  # Start the app with debug mode enabled
