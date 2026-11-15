from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan

security_bp = Blueprint("security", __name__)

@security_bp.route("/security-analysis")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]

    selected_project_id = request.args.get("project_id", type=int)
    severity_filter = request.args.get("severity", "").strip().lower()
    search_query = request.args.get("q", "").strip()

    target_project_ids = [selected_project_id] if selected_project_id else project_ids

    query = Finding.query.filter(
        Finding.project_id.in_(target_project_ids),
        Finding.category == "security"
    )

    if severity_filter:
        query = query.filter(Finding.severity == severity_filter)
    if search_query:
        query = query.filter(
            (Finding.title.ilike(f"%{search_query}%")) |
            (Finding.file_path.ilike(f"%{search_query}%")) |
            (Finding.rule_id.ilike(f"%{search_query}%"))
        )

    findings = query.order_by(Finding.id.desc()).all()

    # Security metrics
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    secret_leaks = sum(1 for f in findings if any(k in f.rule_id for k in ("KEY", "TOKEN", "PASS", "PRIV")))
    injection_risks = sum(1 for f in findings if any(k in f.rule_id for k in ("SQL", "CMD", "INJECT")))
    insecure_configs = sum(1 for f in findings if any(k in f.rule_id for k in ("DEBUG", "SSL", "CORS")))

    scans = Scan.query.filter(Scan.project_id.in_(target_project_ids), Scan.status == "completed").all()
    avg_security = round(sum(s.security_score for s in scans) / len(scans), 1) if scans else 100.0

    return render_template(
        "security_analysis.html",
        projects=projects,
        selected_project_id=selected_project_id,
        severity_filter=severity_filter,
        search_query=search_query,
        findings=findings,
        avg_security=avg_security,
        critical_count=critical_count,
        high_count=high_count,
        secret_leaks=secret_leaks,
        injection_risks=injection_risks,
        insecure_configs=insecure_configs
    )
