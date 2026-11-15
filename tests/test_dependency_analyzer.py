import tempfile
from pathlib import Path
from app.engines.dependency_analyzer import analyze_dependency_file

def test_detects_vulnerable_requests_package():
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "requirements.txt"
        temp_path.write_text("requests==2.28.1\nurllib3==1.26.15\nflask==2.3.2\n", encoding="utf-8")
        findings, packages = analyze_dependency_file(temp_path)
        assert len(packages) == 3
        # Should flag requests 2.28.1 and urllib3 1.26.15 from offline CVE registry
        vuln_rules = [f["rule_id"] for f in findings]
        assert any("CVE-2023-32681" in r for r in vuln_rules)

def test_detects_vulnerable_package_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "package.json"
        temp_path.write_text('{"name": "test-app", "dependencies": {"lodash": "4.17.15", "axios": "0.21.1"}}', encoding="utf-8")
        findings, packages = analyze_dependency_file(temp_path)
        assert len(packages) == 2
        vuln_rules = [f["rule_id"] for f in findings]
        assert any("CVE-2021-23337" in r or "CVE-2020-8203" in r for r in vuln_rules)
