from extensions import db

class ProjectFile(db.Model):
    __tablename__ = "project_files"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    file_path = db.Column(db.String(500), nullable=False)
    relative_path = db.Column(db.String(500), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    extension = db.Column(db.String(50), default="")
    file_size_bytes = db.Column(db.BigInteger, default=0)
    line_count = db.Column(db.Integer, default=0)
    language = db.Column(db.String(50), default="Unknown")
    is_analyzed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    project = db.relationship("Project", back_populates="files")
