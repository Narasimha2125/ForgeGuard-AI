import io
import zipfile
import pytest
from app.services.repository_service import safe_extract_archive

class DummyFileStorage:
    def __init__(self, buffer, filename="archive.zip"):
        self.buffer = buffer
        self.filename = filename

    def save(self, destination):
        with open(destination, "wb") as f:
            f.write(self.buffer.getvalue())

def test_zip_path_traversal_rejected(temp_storage, app):
    # Construct malicious ZIP with ../ traversal
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0::/root:/bin/bash")
    buf.seek(0)

    storage = DummyFileStorage(buf, "evil.zip")
    with app.app_context():
        with pytest.raises(ValueError, match="Unsafe path traversal"):
            safe_extract_archive(storage, project_id=999, storage_root=temp_storage)

def test_safe_zip_extraction(temp_storage, app):
    # Construct normal safe ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/main.py", "def hello(): return 'world'\n")
        zf.writestr("requirements.txt", "flask==3.0.0\n")
        zf.writestr("node_modules/junk.js", "console.log('exclude me')")
    buf.seek(0)

    storage = DummyFileStorage(buf, "safe.zip")
    with app.app_context():
        target_dir, primary_lang, file_count, total_bytes, lang_breakdown = safe_extract_archive(
            storage, project_id=101, storage_root=temp_storage
        )
        assert primary_lang == "Python"
        # node_modules should be excluded
        assert file_count == 2
