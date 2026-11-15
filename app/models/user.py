from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db, login_manager

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="developer")
    avatar_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    projects = db.relationship("Project", back_populates="owner", lazy=True, cascade="all, delete-orphan")
    settings = db.relationship("UserSetting", back_populates="user", uselist=False, cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="user", lazy=True, cascade="all, delete-orphan")
    integrations = db.relationship("Integration", back_populates="user", lazy=True, cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_or_create_settings(self):
        from app.models.user_setting import UserSetting
        if not self.settings:
            s = UserSetting(user_id=self.id)
            db.session.add(s)
            db.session.commit()
            return s
        return self.settings

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
