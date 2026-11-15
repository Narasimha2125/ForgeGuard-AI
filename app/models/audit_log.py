from extensions import db

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)  # project_create, scan_start, finding_status_change, etc.
    resource_type = db.Column(db.String(50), nullable=False)        # project, scan, finding, setting
    resource_id = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, default="")
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), index=True)

    user = db.relationship("User", back_populates="audit_logs")
