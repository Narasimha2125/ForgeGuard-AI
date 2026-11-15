import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-development-secret-for-forgeguard-ai")
    
    # Database: MySQL with SQLite local fallback
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + str(BASE_DIR / "forgeguard_dev.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Large upload handling: Configurable via environment variable, default 500 MB (not hardcoded 50 MB)
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_SIZE_MB", "500")) * 1024 * 1024
    
    # Storage directories
    STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", str(BASE_DIR / "storage"))).resolve()
    UPLOAD_FOLDER = str(STORAGE_ROOT / "uploads")
    REPORTS_FOLDER = str(STORAGE_ROOT / "reports")
    
    # Security & Scanner limits
    MAX_FILE_EXTRACTION_MB = int(os.getenv("MAX_FILE_EXTRACTION_MB", "100"))  # per file limit
    MAX_TOTAL_EXTRACTION_MB = int(os.getenv("MAX_TOTAL_EXTRACTION_MB", "1000")) # total archive limit
    MAX_ARCHIVE_FILES = int(os.getenv("MAX_ARCHIVE_FILES", "25000"))
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
    
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    
    # OSV API for dependency scanning
    OSV_API_URL = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/query")
    
    # GitHub Integration
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
