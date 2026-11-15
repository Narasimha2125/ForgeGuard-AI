from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from extensions import db
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.project_file import ProjectFile

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    project_ids = [p.id for p in projects]

    scans = Scan.query.filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all() if project_ids else []
    recent_scans = scans[:5]
    latest_scan = scans[0] if scans else None

    # Aggregate counts
    total_repos = len(projects)
    total_scans = len(scans)
    total_files_analyzed = sum(s.files_scanned for s in scans)
    
    # Active open findings for current user
    all_findings = Finding.query.filter(Finding.project_id.in_(project_ids)).all() if project_ids else []
    open_findings = [f for f in all_findings if f.status == "open"]
    resolved_findings = [f for f in all_findings if f.status == "resolved"]

    critical_count = sum(1 for f in open_findings if f.severity == "critical")
    high_count = sum(1 for f in open_findings if f.severity == "high")
    medium_count = sum(1 for f in open_findings if f.severity == "medium")
    low_count = sum(1 for f in open_findings if f.severity in ("low", "info"))

    # Health scores from completed scans or latest scan
    completed_scans = [s for s in scans if s.status == "completed"]
    if completed_scans:
        avg_health = round(sum(s.health_score for s in completed_scans) / len(completed_scans), 1)
        avg_security = round(sum(s.security_score for s in completed_scans) / len(completed_scans), 1)
        avg_dependency = round(sum(s.dependency_score for s in completed_scans) / len(completed_scans), 1)
        avg_quality = round(sum(s.quality_score for s in completed_scans) / len(completed_scans), 1)
    else:
        avg_health = 100.0
        avg_security = 100.0
        avg_dependency = 100.0
        avg_quality = 100.0

    # Project health distribution
    health_dist = {"Excellent": 0, "Good": 0, "Needs Improvement": 0, "Poor": 0}
    for p in projects:
        if p.latest_scan and p.latest_scan.health_label:
            lbl = p.latest_scan.health_label
            health_dist[lbl] = health_dist.get(lbl, 0) + 1
        else:
            health_dist["Excellent"] += 1

    # Language distribution
    lang_counts = {}
    if project_ids:
        lang_rows = db.session.query(ProjectFile.language, func.count(ProjectFile.id))\
            .filter(ProjectFile.project_id.in_(project_ids))\
            .group_by(ProjectFile.language).all()
        for lang, cnt in lang_rows:
            if lang:
                lang_counts[lang] = cnt

    # Scan activity counts
    scan_activity = {
        "completed": sum(1 for s in scans if s.status == "completed"),
        "failed": sum(1 for s in scans if s.status == "failed"),
        "running": sum(1 for s in scans if s.status in ("running", "pending"))
    }

    # Trend data (last 8 completed scans chronological)
    trend_scans = sorted(completed_scans, key=lambda s: s.id)[-8:]
    trend_labels = [f"Scan #{s.id} ({s.project.name[:10]})" for s in trend_scans]
    trend_quality = [s.quality_score for s in trend_scans]
    trend_security = [s.security_score for s in trend_scans]
    trend_findings = [s.findings_count for s in trend_scans]

    # Top issues & most affected files
    rule_counts = {}
    file_counts = {}
    for f in open_findings:
        rule_counts[f.title] = rule_counts.get(f.title, 0) + 1
        file_counts[f.file_path] = file_counts.get(f.file_path, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_affected_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_critical_findings = [f for f in open_findings if f.severity in ("critical", "high")][:6]

    return render_template(
        "dashboard.html",
        total_repos=total_repos,
        total_scans=total_scans,
        total_files_analyzed=total_files_analyzed,
        total_findings=len(open_findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        resolved_count=len(resolved_findings),
        overall_health=avg_health,
        security_score=avg_security,
        dependency_score=avg_dependency,
        quality_score=avg_quality,
        latest_scan=latest_scan,
        projects=projects,
        recent_scans=recent_scans,
        # Chart Data
        severity_chart_data={
            "labels": ["Critical", "High", "Medium", "Low"],
            "data": [critical_count, high_count, medium_count, low_count]
        },
        health_dist_data={
            "labels": list(health_dist.keys()),
            "data": list(health_dist.values())
        },
        trend_chart_data={
            "labels": trend_labels,
            "quality": trend_quality,
            "security": trend_security,
            "findings": trend_findings
        },
        language_chart_data={
            "labels": list(lang_counts.keys())[:8],
            "data": list(lang_counts.values())[:8]
        },
        scan_activity_data={
            "labels": ["Completed", "Failed", "In Progress"],
            "data": [scan_activity["completed"], scan_activity["failed"], scan_activity["running"]]
        },
        top_rules=top_rules,
        top_affected_files=top_affected_files,
        top_critical_findings=top_critical_findings
    )
