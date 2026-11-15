from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.project_file import ProjectFile

dependencies_bp = Blueprint("dependencies", __name__)

@dependencies_bp.route("/dependency-analysis")
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
        Finding.category == "dependency"
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

    # Manifest files discovered
    manifest_files = ProjectFile.query.filter(
        ProjectFile.project_id.in_(target_project_ids),
        ProjectFile.file_name.in_([
            "requirements.txt", "package.json", "package-lock.json",
            "pyproject.toml", "Cargo.toml", "go.mod", "pom.xml"
        ])
    ).all() if target_project_ids else []

    scans = Scan.query.filter(Scan.project_id.in_(target_project_ids), Scan.status == "completed").all()
    avg_dependency_score = round(sum(s.dependency_score for s in scans) / len(scans), 1) if scans else 100.0

    critical_vulns = sum(1 for f in findings if f.severity == "critical")
    high_vulns = sum(1 for f in findings if f.severity == "high")
    medium_vulns = sum(1 for f in findings if f.severity == "medium")

    return render_template(
        "dependency_analysis.html",
        projects=projects,
        selected_project_id=selected_project_id,
        severity_filter=severity_filter,
        search_query=search_query,
        findings=findings,
        manifest_files=manifest_files,
        avg_dependency_score=avg_dependency_score,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        medium_vulns=medium_vulns,
        total_vulns=len(findings)
    )
