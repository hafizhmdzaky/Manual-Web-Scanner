# config.py
import os


class Config:
    # Basic configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'

    # Scanner configuration
    MAX_PAGES = 100
    REQUEST_TIMEOUT = 10
    DELAY_BETWEEN_REQUESTS = 1
    MAX_THREADS = 5

    # User agents for rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///scanner.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False