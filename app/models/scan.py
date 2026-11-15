from extensions import db
from datetime import datetime

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    status = db.Column(db.String(30), default="pending")  # pending, running, completed, failed, cancelled
    current_stage = db.Column(db.String(100), default="Initialized")
    current_stage_number = db.Column(db.Integer, default=0)
    progress_percent = db.Column(db.Integer, default=0)
    files_scanned = db.Column(db.Integer, default=0)
    files_skipped = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    risk_score = db.Column(db.Float, default=0.0)
    health_score = db.Column(db.Float, default=100.0)
    health_label = db.Column(db.String(30), default="Excellent")
    security_score = db.Column(db.Float, default=100.0)
    quality_score = db.Column(db.Float, default=100.0)
    dependency_score = db.Column(db.Float, default=100.0)
    maintainability_score = db.Column(db.Float, default=100.0)
    
    error_message = db.Column(db.Text, nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    project = db.relationship("Project", back_populates="scans")
    stages = db.relationship("ScanStage", back_populates="scan", lazy=True, cascade="all, delete-orphan", order_by="ScanStage.stage_number")
    findings = db.relationship("Finding", back_populates="scan", lazy=True, cascade="all, delete-orphan")
    metrics = db.relationship("ProjectMetric", back_populates="scan", lazy=True, cascade="all, delete-orphan")
    risk_assessment = db.relationship("RiskAssessment", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    reports = db.relationship("Report", back_populates="scan", lazy=True, cascade="all, delete-orphan")

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 1)
        return 0.0
