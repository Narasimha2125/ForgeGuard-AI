from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.risk_assessment import RiskAssessment

risk_bp = Blueprint("risk", __name__)

@risk_bp.route("/risk-assessment")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]

    selected_project_id = request.args.get("project_id", type=int)
    target_project_ids = [selected_project_id] if selected_project_id else project_ids

    scans = Scan.query.filter(Scan.project_id.in_(target_project_ids), Scan.status == "completed").order_by(Scan.created_at.desc()).all()
    latest_scan = scans[0] if scans else None
    
    risk_assessment = latest_scan.risk_assessment if latest_scan else None

    # Priority remediation findings
    findings = Finding.query.filter(
        Finding.project_id.in_(target_project_ids),
        Finding.status == "open"
    ).all() if target_project_ids else []

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    prioritized_findings = sorted(findings, key=lambda f: sev_order.get(f.severity.lower(), 5))[:15]

    overall_risk = latest_scan.risk_score if latest_scan else 0.0
    security_risk = (100.0 - latest_scan.security_score) if latest_scan else 0.0
    quality_risk = (100.0 - latest_scan.quality_score) if latest_scan else 0.0
    dependency_risk = (100.0 - latest_scan.dependency_score) if latest_scan else 0.0

    return render_template(
        "risk_assessment.html",
        projects=projects,
        selected_project_id=selected_project_id,
        latest_scan=latest_scan,
        risk_assessment=risk_assessment,
        overall_risk=round(overall_risk, 1),
        security_risk=round(security_risk, 1),
        quality_risk=round(quality_risk, 1),
        dependency_risk=round(dependency_risk, 1),
        prioritized_findings=prioritized_findings
    )
