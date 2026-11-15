from extensions import db

class Integration(db.Model):
    __tablename__ = "integrations"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    provider = db.Column(db.String(50), default="github")  # github, gitlab, bitbucket
    account_name = db.Column(db.String(100), default="")
    access_token = db.Column(db.String(255), nullable=True)  # stored securely/masked in views
    webhook_secret = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship("User", back_populates="integrations")
