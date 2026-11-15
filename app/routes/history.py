from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.scan_comparison import ScanComparison
from extensions import db

history_bp = Blueprint("history", __name__)

@history_bp.route("/scan-history")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]

    selected_project_id = request.args.get("project_id", type=int)
    status_filter = request.args.get("status", "").strip().lower()

    query = Scan.query.filter(Scan.project_id.in_(project_ids))
    if selected_project_id:
        query = query.filter(Scan.project_id == selected_project_id)
    if status_filter:
        query = query.filter(Scan.status == status_filter)

    scans = query.order_by(Scan.created_at.desc()).all()

    return render_template(
        "scan_history.html",
        projects=projects,
        selected_project_id=selected_project_id,
        status_filter=status_filter,
        scans=scans
    )

@history_bp.route("/compare")
@login_required
def compare():
    base_id = request.args.get("base_id", type=int)
    target_id = request.args.get("target_id", type=int)
    
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()

    if not base_id or not target_id:
        return render_template("compare.html", projects=projects, base_scan=None, target_scan=None)

    base_scan = Scan.query.get_or_404(base_id)
    target_scan = Scan.query.get_or_404(target_id)

    if base_scan.project.user_id != current_user.id or target_scan.project.user_id != current_user.id:
        flash("Unauthorized to compare these scans.", "danger")
        return redirect(url_for("history.index"))

    base_findings = {f.fingerprint: f for f in base_scan.findings if f.fingerprint}
    target_findings = {f.fingerprint: f for f in target_scan.findings if f.fingerprint}

    # Identify New, Resolved, and Persistent findings
    new_fingerprints = set(target_findings.keys()) - set(base_findings.keys())
    resolved_fingerprints = set(base_findings.keys()) - set(target_findings.keys())
    persistent_fingerprints = set(base_findings.keys()) & set(target_findings.keys())

    new_findings = [target_findings[fp] for fp in new_fingerprints]
    resolved_findings = [base_findings[fp] for fp in resolved_fingerprints]
    persistent_findings = [target_findings[fp] for fp in persistent_fingerprints]

    health_diff = round(target_scan.health_score - base_scan.health_score, 1)
    risk_diff = round(target_scan.risk_score - base_scan.risk_score, 1)

    return render_template(
        "compare.html",
        projects=projects,
        base_scan=base_scan,
        target_scan=target_scan,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persistent_findings=persistent_findings,
        health_diff=health_diff,
        risk_diff=risk_diff
    )
