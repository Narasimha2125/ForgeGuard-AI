from extensions import db
import hashlib

class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    rule_id = db.Column(db.String(100), nullable=False, index=True)
    category = db.Column(db.String(50), default="code_quality", index=True)  # security, code_quality, dependency, architecture
    severity = db.Column(db.String(20), default="low", index=True)          # critical, high, medium, low, info
    confidence = db.Column(db.String(20), default="medium")                 # high, medium, low
    
    file_path = db.Column(db.String(500), nullable=False, index=True)
    line_number = db.Column(db.Integer, nullable=True)
    column_number = db.Column(db.Integer, nullable=True)
    code_snippet = db.Column(db.Text, nullable=True)
    
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, default="")
    technical_explanation = db.Column(db.Text, default="")
    why_it_matters = db.Column(db.Text, default="")
    recommendation = db.Column(db.Text, default="")
    suggested_fix = db.Column(db.Text, default="")
    detection_tool = db.Column(db.String(100), default="ForgeGuard Core")
    
    fingerprint = db.Column(db.String(64), nullable=True, index=True)
    status = db.Column(db.String(30), default="open", index=True)  # open, in_progress, resolved, accepted_risk, false_positive, ignored
    resolution_notes = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    scan = db.relationship("Scan", back_populates="findings")
    recommendations = db.relationship("Recommendation", back_populates="finding", lazy=True, cascade="all, delete-orphan")

    def generate_fingerprint(self):
        raw = f"{self.project_id}:{self.file_path}:{self.rule_id}:{self.title}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint
