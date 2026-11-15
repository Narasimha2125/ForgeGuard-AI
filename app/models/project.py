from extensions import db

class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    language = db.Column(db.String(60), default="Unknown")
    source_path = db.Column(db.String(500), nullable=True)
    archive_filename = db.Column(db.String(255), nullable=True)
    total_size_bytes = db.Column(db.BigInteger, default=0)
    file_count = db.Column(db.Integer, default=0)
    excluded_dirs = db.Column(db.Text, default="node_modules,.git,.venv,venv,__pycache__,dist,build,coverage,vendor")
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    owner = db.relationship("User", back_populates="projects")
    scans = db.relationship("Scan", back_populates="project", lazy=True, cascade="all, delete-orphan", order_by="desc(Scan.id)")
    files = db.relationship("ProjectFile", back_populates="project", lazy=True, cascade="all, delete-orphan")
    reports = db.relationship("Report", back_populates="project", lazy=True, cascade="all, delete-orphan")

    @property
    def latest_scan(self):
        return self.scans[0] if self.scans else None
