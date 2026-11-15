from extensions import db

class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    report_format = db.Column(db.String(10), nullable=False)  # pdf, csv, json
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size_bytes = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    scan = db.relationship("Scan", back_populates="reports")
    project = db.relationship("Project", back_populates="reports")
