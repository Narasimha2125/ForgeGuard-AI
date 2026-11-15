from extensions import db

class ProjectMetric(db.Model):
    __tablename__ = "project_metrics"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    metric_category = db.Column(db.String(50), default="general")  # general, quality, security, dependencies, maintainability
    metric_name = db.Column(db.String(100), nullable=False, index=True)
    metric_value = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    scan = db.relationship("Scan", back_populates="metrics")
