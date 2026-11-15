from extensions import db

class Recommendation(db.Model):
    __tablename__ = "recommendations"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("findings.id"), nullable=False, index=True)
    priority = db.Column(db.String(20), default="medium")  # critical, high, medium, low
    title = db.Column(db.String(255), default="")
    plain_explanation = db.Column(db.Text, default="")
    technical_explanation = db.Column(db.Text, default="")
    proposed_diff = db.Column(db.Text, default="")
    doc_links = db.Column(db.Text, default="")
    status = db.Column(db.String(30), default="open")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    finding = db.relationship("Finding", back_populates="recommendations")
