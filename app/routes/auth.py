from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from app.models.user import User
from app.models.user_setting import UserSetting
from app.models.audit_log import AuditLog

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Enter your name, valid email and a password of at least 8 characters.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "warning")
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.flush()

            # Initialize user settings
            settings = UserSetting(user_id=user.id)
            db.session.add(settings)

            # Audit log
            log = AuditLog(
                user_id=user.id,
                action="user_registered",
                resource_type="user",
                resource_id=str(user.id),
                details=f"User {name} ({email}) created an account."
            )
            db.session.add(log)
            db.session.commit()

            login_user(user)
            flash("Welcome to ForgeGuard AI! Your workspace is ready.", "success")
            return redirect(url_for("dashboard.index"))
    return render_template("auth.html", mode="Register")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            log = AuditLog(
                user_id=user.id,
                action="user_logged_in",
                resource_type="user",
                resource_id=str(user.id),
                details=f"User logged in from {request.remote_addr}"
            )
            db.session.add(log)
            db.session.commit()
            return redirect(url_for("dashboard.index"))
        flash("Invalid email or password.", "danger")
    return render_template("auth.html", mode="Login")

@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
