from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from extensions import db
from app.models.integration import Integration
from app.models.audit_log import AuditLog
from app.services.github_service import (
    get_github_integration,
    verify_and_save_github_token,
    fetch_user_github_repositories,
    import_github_repository
)
from app.services.scanner_service import create_initial_scan, launch_background_scan
from flask import current_app

integrations_bp = Blueprint("integrations", __name__)

@integrations_bp.route("/integrations")
@login_required
def index():
    github_integration = get_github_integration(current_user.id)
    github_repos = []
    
    if github_integration and github_integration.access_token:
        try:
            github_repos = fetch_user_github_repositories(github_integration.access_token)
        except Exception:
            github_repos = []

    return render_template(
        "integrations.html",
        github_integration=github_integration,
        github_repos=github_repos
    )

@integrations_bp.route("/integrations/github/connect", methods=["POST"])
@login_required
def connect_github():
    token = request.form.get("personal_access_token", "").strip()
    if not token:
        flash("Personal Access Token cannot be empty.", "danger")
        return redirect(url_for("integrations.index"))

    try:
        integration = verify_and_save_github_token(current_user.id, token)
        db.session.add(AuditLog(
            user_id=current_user.id,
            action="connect_github",
            resource_type="integration",
            resource_id=str(integration.id),
            details=f"Connected GitHub account @{integration.account_name}"
        ))
        db.session.commit()
        flash(f"GitHub account @{integration.account_name} connected successfully!", "success")
    except ValueError as exc:
        flash(str(exc), "danger")

    return redirect(url_for("integrations.index"))

@integrations_bp.route("/integrations/github/disconnect", methods=["POST"])
@login_required
def disconnect_github():
    integration = get_github_integration(current_user.id)
    if integration:
        integration.is_active = False
        integration.access_token = None
        db.session.commit()
        flash("GitHub integration disconnected.", "info")
    return redirect(url_for("integrations.index"))

@integrations_bp.route("/integrations/github/import", methods=["POST"])
@login_required
def import_repo():
    repo_name = request.form.get("repo_full_name", "").strip()
    auto_scan = request.form.get("auto_scan") == "1"

    if not repo_name:
        flash("Repository full name is required.", "danger")
        return redirect(url_for("integrations.index"))

    try:
        project = import_github_repository(current_user.id, repo_name)
        flash(f"Repository '{repo_name}' imported successfully into ForgeGuard.", "success")
        
        if auto_scan:
            scan = create_initial_scan(project.id)
            launch_background_scan(current_app, scan.id)
            flash(f"Initial scan #{scan.id} queued automatically.", "info")
            return redirect(url_for("scans.detail", scan_id=scan.id))

        return redirect(url_for("projects.detail", project_id=project.id))
    except Exception as exc:
        flash(f"GitHub Import Failed: {str(exc)}", "danger")
        return redirect(url_for("integrations.index"))

@integrations_bp.route("/api/webhooks/github", methods=["POST"])
def github_webhook():
    event = request.headers.get("X-GitHub-Event")
    if event == "ping":
        return jsonify({"msg": "pong"}), 200
    # Acknowledge receipt
    return jsonify({"status": "received", "event": event}), 200
