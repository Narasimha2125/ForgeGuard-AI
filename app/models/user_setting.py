from extensions import db

class UserSetting(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True, index=True)
    theme = db.Column(db.String(20), default="dark")
    scan_timeout_seconds = db.Column(db.Integer, default=300)
    default_excluded_dirs = db.Column(db.Text, default="node_modules,.git,.venv,venv,__pycache__,dist,build,coverage,vendor,.idea,.vscode")
    max_file_size_mb = db.Column(db.Integer, default=50)
    notify_on_scan_complete = db.Column(db.Boolean, default=True)
    notify_on_critical_findings = db.Column(db.Boolean, default=True)
    notify_on_security_alerts = db.Column(db.Boolean, default=True)
    github_access_token = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    user = db.relationship("User", back_populates="settings")
