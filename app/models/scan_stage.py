from extensions import db

class ScanStage(db.Model):
    __tablename__ = "scan_stages"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    stage_number = db.Column(db.Integer, nullable=False)
    stage_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(30), default="pending")  # pending, running, completed, failed, skipped
    message = db.Column(db.String(255), default="")
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    scan = db.relationship("Scan", back_populates="stages")
