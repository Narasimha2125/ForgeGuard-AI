from flask import Flask
from config import Config
from extensions import db, login_manager, migrate
from pathlib import Path

def create_app(config_class=Config):
    flask_app = Flask(__name__)
    flask_app.config.from_object(config_class)

    Path(flask_app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(flask_app.config["REPORTS_FOLDER"]).mkdir(parents=True, exist_ok=True)
    
    db.init_app(flask_app)
    login_manager.init_app(flask_app)
    migrate.init_app(flask_app, db)

    # Register Blueprints for all 12 platform modules
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.projects import projects_bp
    from app.routes.scans import scans_bp
    from app.routes.code_quality import code_quality_bp
    from app.routes.security import security_bp
    from app.routes.dependencies import dependencies_bp
    from app.routes.risk import risk_bp
    from app.routes.history import history_bp
    from app.routes.findings import findings_bp
    from app.routes.reports import reports_bp
    from app.routes.notifications import notifications_bp
    from app.routes.integrations import integrations_bp
    from app.routes.settings import settings_bp

    flask_app.register_blueprint(auth_bp)
    flask_app.register_blueprint(dashboard_bp)
    flask_app.register_blueprint(projects_bp, url_prefix="/projects")
    flask_app.register_blueprint(scans_bp, url_prefix="/scans")
    flask_app.register_blueprint(code_quality_bp)
    flask_app.register_blueprint(security_bp)
    flask_app.register_blueprint(dependencies_bp)
    flask_app.register_blueprint(risk_bp)
    flask_app.register_blueprint(history_bp)
    flask_app.register_blueprint(findings_bp, url_prefix="/findings")
    flask_app.register_blueprint(reports_bp, url_prefix="/reports")
    flask_app.register_blueprint(notifications_bp)
    flask_app.register_blueprint(integrations_bp)
    flask_app.register_blueprint(settings_bp, url_prefix="/settings")

    with flask_app.app_context():
        import app.models as _models  # noqa: F401
        db.create_all()

    return flask_app
