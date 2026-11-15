from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime
from extensions import db
from app.models.project import Project
from app.models.scan import Scan
from app.models.scan_stage import ScanStage
from app.models.finding import Finding
from app.models.audit_log import AuditLog
from app.services.scanner_service import create_initial_scan, launch_background_scan

scans_bp = Blueprint("scans", __name__)

@scans_bp.route("/")
@login_required
def index():
    """Repository Scanner launcher and live scanning console."""
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]
    active_scans = Scan.query.filter(
        Scan.project_id.in_(project_ids),
        Scan.status.in_(["pending", "running"])
    ).order_by(Scan.started_at.desc()).all() if project_ids else []
    
    recent_scans = Scan.query.filter(
        Scan.project_id.in_(project_ids)
    ).order_by(Scan.created_at.desc()).limit(10).all() if project_ids else []

    selected_project_id = request.args.get("project_id", type=int)

    return render_template(
        "scanner.html",
        projects=projects,
        active_scans=active_scans,
        recent_scans=recent_scans,
        selected_project_id=selected_project_id
    )

@scans_bp.route("/start", methods=["POST"])
@login_required
def start():
    project_id = request.form.get("project_id", type=int)
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    
    # Selected analysis categories
    categories = request.form.getlist("categories")
    if not categories:
        categories = ["quality", "security", "dependency", "architecture"]

    # Prevent concurrent scans on the same project
    existing_running = Scan.query.filter_by(project_id=project.id, status="running").first()
    if existing_running:
        flash(f"A scan is already in progress for '{project.name}' (Scan #{existing_running.id}).", "warning")
        return redirect(url_for("scans.detail", scan_id=existing_running.id))

    # Initialize scan and launch background thread
    scan = create_initial_scan(project.id)
    launch_background_scan(current_app, scan.id, categories)

    db.session.add(AuditLog(
        user_id=current_user.id,
        action="start_scan",
        resource_type="scan",
        resource_id=str(scan.id),
        details=f"Launched scan on {project.name} with categories: {', '.join(categories)}"
    ))
    db.session.commit()

    flash(f"Scan #{scan.id} started for '{project.name}'.", "info")
    return redirect(url_for("scans.detail", scan_id=scan.id))

@scans_bp.route("/<int:scan_id>")
@login_required
def detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.project.user_id != current_user.id:
        flash("Unauthorized access to scan.", "danger")
        return redirect(url_for("scans.index"))

    stages = ScanStage.query.filter_by(scan_id=scan.id).order_by(ScanStage.stage_number).all()
    findings = Finding.query.filter_by(scan_id=scan.id).order_by(Finding.id).all()
    
    # Severity breakdown
    sev_counts = {
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "info": sum(1 for f in findings if f.severity == "info")
    }

    return render_template(
        "scan_detail.html",
        scan=scan,
        project=scan.project,
        stages=stages,
        findings=findings,
        sev_counts=sev_counts
    )

@scans_bp.route("/<int:scan_id>/progress")
@login_required
def progress(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.project.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    stages = ScanStage.query.filter_by(scan_id=scan.id).order_by(ScanStage.stage_number).all()
    elapsed = 0.0
    if scan.started_at:
        end_time = scan.completed_at or datetime.utcnow()
        elapsed = round((end_time - scan.started_at).total_seconds(), 1)

    return jsonify({
        "id": scan.id,
        "status": scan.status,
        "current_stage": scan.current_stage,
        "current_stage_number": scan.current_stage_number,
        "progress_percent": scan.progress_percent,
        "files_scanned": scan.files_scanned,
        "files_skipped": scan.files_skipped,
        "findings_count": scan.findings_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "health_score": scan.health_score,
        "health_label": scan.health_label,
        "error_message": scan.error_message,
        "elapsed_seconds": elapsed,
        "stages": [
            {
                "number": st.stage_number,
                "name": st.stage_name,
                "status": st.status,
                "message": st.message
            } for st in stages
        ]
    })

@scans_bp.route("/<int:scan_id>/cancel", methods=["POST"])
@login_required
def cancel(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.project.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("scans.index"))

    if scan.status in ("running", "pending"):
        scan.status = "cancelled"
        scan.current_stage = "Cancelled by user"
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        flash(f"Scan #{scan.id} cancelled.", "warning")
    return redirect(url_for("scans.detail", scan_id=scan.id))

@scans_bp.route("/<int:scan_id>/retry", methods=["POST"])
@login_required
def retry(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.project.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("scans.index"))

    project = scan.project
    new_scan = create_initial_scan(project.id)
    launch_background_scan(current_app, new_scan.id)
    flash(f"Restarted scan as #{new_scan.id}.", "info")
    return redirect(url_for("scans.detail", scan_id=new_scan.id))
