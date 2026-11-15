import io
import zipfile
import time
from app.models.project import Project
from app.models.user import User
from app.models.scan import Scan
from extensions import db
from app.services.repository_service import safe_extract_archive
from app.services.scanner_service import create_initial_scan, _run_scan_thread
from tests.test_zip_security import DummyFileStorage

def test_full_scan_lifecycle(app, temp_storage):
    with app.app_context():
        user = User(name="Scan Tester", email="scanner@forgeguard.local")
        user.set_password("Pass12345!")
        db.session.add(user)
        db.session.commit()

        project = Project(user_id=user.id, name="demo-repo", description="Testing scanner")
        db.session.add(project)
        db.session.commit()

        # Create zip with intentional flaws
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("app.py", 'AWS_KEY = "AKIA1234567890ABCDEF"\nresult = eval(user_input)\n')
            zf.writestr("requirements.txt", "requests==2.28.1\n")
        buf.seek(0)

        storage = DummyFileStorage(buf, "demo.zip")
        target_dir, primary_lang, file_count, total_bytes, _ = safe_extract_archive(
            storage, project.id, temp_storage
        )
        project.source_path = target_dir
        project.language = primary_lang
        project.file_count = file_count
        db.session.commit()

        # Initialize scan
        scan = create_initial_scan(project.id)
        assert len(scan.stages) == 11
        assert scan.status == "pending"

        # Execute scan pipeline
        _run_scan_thread(app, scan.id, ["quality", "security", "dependency", "architecture"])

        db.session.refresh(scan)
        assert scan.status == "completed"
        assert scan.progress_percent == 100
        assert scan.findings_count >= 2
        # Check that critical secret was captured
        assert scan.critical_count >= 1
        assert scan.health_score < 100.0
