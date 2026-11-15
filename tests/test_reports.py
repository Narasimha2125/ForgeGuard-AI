from pathlib import Path
from app.models.project import Project
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from extensions import db
from app.services.report_service import generate_csv_report, generate_json_report, generate_pdf_report

def test_reports_generation(app):
    with app.app_context():
        u = User(name="Reporter", email="rep@forgeguard.local")
        u.set_password("Secret123!")
        db.session.add(u)
        db.session.commit()

        p = Project(user_id=u.id, name="TestReportProject")
        db.session.add(p)
        db.session.commit()

        s = Scan(project_id=p.id, status="completed", files_scanned=5, findings_count=1, health_score=85.0)
        db.session.add(s)
        db.session.commit()

        f = Finding(
            project_id=p.id,
            scan_id=s.id,
            rule_id="SEC-TEST-001",
            category="security",
            severity="high",
            title="Sample Test Finding",
            file_path="sample.py",
            recommendation="Fix this issue"
        )
        db.session.add(f)
        db.session.commit()

        csv_rep = generate_csv_report(s.id)
        assert Path(csv_rep.file_path).exists()
        assert csv_rep.report_format == "csv"

        json_rep = generate_json_report(s.id)
        assert Path(json_rep.file_path).exists()
        assert json_rep.report_format == "json"

        pdf_rep = generate_pdf_report(s.id)
        assert Path(pdf_rep.file_path).exists()
        assert pdf_rep.report_format == "pdf"
