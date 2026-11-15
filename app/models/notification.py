from extensions import db

class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), default="info")  # scan_complete, scan_failed, critical_finding, security_alert, report_ready, integration
    severity = db.Column(db.String(20), default="info")          # info, warning, danger, success
    link_url = db.Column(db.String(300), nullable=True)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    user = db.relationship("User", back_populates="notifications")
