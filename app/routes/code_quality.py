from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan

code_quality_bp = Blueprint("code_quality", __name__)

@code_quality_bp.route("/code-quality")
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
        Finding.category == "code_quality"
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

    # Metrics
    complexity_count = sum(1 for f in findings if "COMPLEXITY" in f.rule_id)
    long_func_count = sum(1 for f in findings if "LONG-FUNCTION" in f.rule_id)
    nesting_count = sum(1 for f in findings if "NESTING" in f.rule_id)
    unused_import_count = sum(1 for f in findings if "UNUSED-IMPORT" in f.rule_id)
    syntax_error_count = sum(1 for f in findings if "SYNTAX" in f.rule_id or "PARSE" in f.rule_id)

    # Average Quality Score for target projects
    scans = Scan.query.filter(Scan.project_id.in_(target_project_ids), Scan.status == "completed").all()
    avg_quality = round(sum(s.quality_score for s in scans) / len(scans), 1) if scans else 100.0

    return render_template(
        "code_quality.html",
        projects=projects,
        selected_project_id=selected_project_id,
        severity_filter=severity_filter,
        search_query=search_query,
        findings=findings,
        avg_quality=avg_quality,
        complexity_count=complexity_count,
        long_func_count=long_func_count,
        nesting_count=nesting_count,
        unused_import_count=unused_import_count,
        syntax_error_count=syntax_error_count
    )
