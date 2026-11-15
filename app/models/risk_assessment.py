from extensions import db

class RiskAssessment(db.Model):
    __tablename__ = "risk_assessments"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, unique=True, index=True)
    overall_risk_score = db.Column(db.Float, default=0.0)      # 0 to 100
    security_risk = db.Column(db.Float, default=0.0)          # 0 to 100
    quality_risk = db.Column(db.Float, default=0.0)           # 0 to 100
    dependency_risk = db.Column(db.Float, default=0.0)        # 0 to 100
    risk_level = db.Column(db.String(30), default="Low")      # Critical, High, Medium, Low
    explanation = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    scan = db.relationship("Scan", back_populates="risk_assessment")
