# //
import os

class Config:
    # Use SQLite instead of PostgreSQL
    DB_NAME = os.getenv('DB_NAME', 'moringa_database.db')  # SQLite database file name
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_NAME}'  # Use SQLite URI format

    SECRET_KEY = os.getenv('SECRET_KEY', 'b938eed8627bfeb4563583f22d78e727')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
