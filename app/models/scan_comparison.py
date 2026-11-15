from extensions import db

class ScanComparison(db.Model):
    __tablename__ = "scan_comparisons"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    base_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    target_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    
    new_findings_count = db.Column(db.Integer, default=0)
    resolved_findings_count = db.Column(db.Integer, default=0)
    persistent_findings_count = db.Column(db.Integer, default=0)
    
    health_score_diff = db.Column(db.Float, default=0.0)
    risk_score_diff = db.Column(db.Float, default=0.0)
    summary = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
