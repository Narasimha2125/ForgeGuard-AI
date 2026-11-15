import tempfile
from pathlib import Path
from app.engines.security_analyzer import analyze_security_file, mask_secret

def test_mask_secret():
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"
    assert "EXAMPLE" not in mask_secret("AKIAIOSFODNN7EXAMPLE")

def test_detects_aws_key_and_masks():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write('AWS_KEY = "AKIA1234567890ABCDEF"\n')
        temp_path = Path(f.name)

    try:
        findings = analyze_security_file(temp_path)
        aws_findings = [item for item in findings if item["rule_id"] == "SEC-AWS-KEY-001"]
        assert len(aws_findings) >= 1
        assert "AKIA" in aws_findings[0]["description"]
        assert "1234567890" not in aws_findings[0]["description"]  # Ensure redacted
    finally:
        temp_path.unlink()

def test_detects_command_injection():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write('subprocess.call("ls " + user_input, shell=True)\n')
        temp_path = Path(f.name)

    try:
        findings = analyze_security_file(temp_path)
        cmd_findings = [item for item in findings if item["rule_id"] == "SEC-CMD-INJECT-001"]
        assert len(cmd_findings) >= 1
    finally:
        temp_path.unlink()

def test_detects_sql_injection():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write('cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n')
        temp_path = Path(f.name)

    try:
        findings = analyze_security_file(temp_path)
        sql_findings = [item for item in findings if item["rule_id"] == "SEC-SQL-INJECT-001"]
        assert len(sql_findings) >= 1
    finally:
        temp_path.unlink()

def test_detects_insecure_deserialization():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write('data = pickle.loads(untrusted_payload)\n')
        temp_path = Path(f.name)

    try:
        findings = analyze_security_file(temp_path)
        deserial_findings = [item for item in findings if item["rule_id"] == "SEC-DESERIAL-001"]
        assert len(deserial_findings) >= 1
    finally:
        temp_path.unlink()
