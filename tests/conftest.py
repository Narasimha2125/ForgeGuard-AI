import tempfile
import pytest
from pathlib import Path
from app import create_app
from extensions import db
from app.models.user import User

@pytest.fixture
def temp_storage():
    d = tempfile.mkdtemp(prefix="fg_test_")
    yield d

@pytest.fixture
def app(temp_storage):
    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-secret-key-forgeguard"
        SQLALCHEMY_DATABASE_URI = "sqlite://"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        UPLOAD_FOLDER = str(Path(temp_storage) / "uploads")
        REPORTS_FOLDER = str(Path(temp_storage) / "reports")
        MAX_UPLOAD_SIZE_MB = 100
        MAX_FILE_EXTRACTION_MB = 10
        MAX_TOTAL_EXTRACTION_MB = 50
        MAX_ARCHIVE_FILES = 500

    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client(client, app):
    with app.app_context():
        u = User(name="Test Developer", email="dev@forgeguard.local")
        u.set_password("SecurePassword123!")
        db.session.add(u)
        db.session.commit()
    client.post("/login", data={"email": "dev@forgeguard.local", "password": "SecurePassword123!"}, follow_redirects=True)
    return client
