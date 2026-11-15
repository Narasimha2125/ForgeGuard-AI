from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user, logout_user
from extensions import db
from app.models.user import User
from app.models.user_setting import UserSetting
from app.models.audit_log import AuditLog

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/")
@login_required
def index():
    settings = current_user.get_or_create_settings()
    audit_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.created_at.desc()).limit(15).all()
    return render_template("settings.html", settings=settings, audit_logs=audit_logs)

@settings_bp.route("/profile", methods=["POST"])
@login_required
def update_profile():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()

    if not name or not email:
        flash("Name and email are required.", "danger")
        return redirect(url_for("settings.index"))

    existing = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing:
        flash("Another user is already registered with this email.", "danger")
        return redirect(url_for("settings.index"))

    current_user.name = name
    current_user.email = email
    db.session.commit()
    flash("Profile updated successfully.", "success")
    return redirect(url_for("settings.index"))

@settings_bp.route("/password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_user.check_password(current_password):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("settings.index"))

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "danger")
        return redirect(url_for("settings.index"))

    if new_password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("settings.index"))

    current_user.set_password(new_password)
    db.session.add(AuditLog(
        user_id=current_user.id,
        action="change_password",
        resource_type="user",
        resource_id=str(current_user.id),
        details="Password changed successfully."
    ))
    db.session.commit()
    flash("Password updated successfully.", "success")
    return redirect(url_for("settings.index"))

@settings_bp.route("/preferences", methods=["POST"])
@login_required
def update_preferences():
    settings = current_user.get_or_create_settings()
    settings.default_excluded_dirs = request.form.get("default_excluded_dirs", "").strip()
    settings.scan_timeout_seconds = int(request.form.get("scan_timeout_seconds", 300))
    settings.max_file_size_mb = int(request.form.get("max_file_size_mb", 50))
    settings.notify_on_scan_complete = "notify_on_scan_complete" in request.form
    settings.notify_on_critical_findings = "notify_on_critical_findings" in request.form
    settings.notify_on_security_alerts = "notify_on_security_alerts" in request.form

    db.session.commit()
    flash("Scanner and notification preferences saved.", "success")
    return redirect(url_for("settings.index"))

@settings_bp.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    confirm_text = request.form.get("confirm_text", "").strip()
    if confirm_text != "DELETE":
        flash("Confirmation text must be 'DELETE'.", "danger")
        return redirect(url_for("settings.index"))

    user = User.query.get(current_user.id)
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Your account and all associated projects, scans, and reports have been permanently deleted.", "info")
    return redirect(url_for("auth.login"))
