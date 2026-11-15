from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_login import login_required, current_user
from extensions import db
from app.models.project import Project
from app.models.project_file import ProjectFile
from app.models.scan import Scan
from app.models.finding import Finding
from app.services.repository_service import safe_extract_archive, get_repository_tree
from app.models.audit_log import AuditLog

projects_bp = Blueprint("projects", __name__)

@projects_bp.route("/")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.created_at.desc()).all()
    return render_template("projects.html", projects=projects)

@projects_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        custom_exclusions = request.form.get("custom_exclusions", "").strip()
        upload = request.files.get("archive")

        if not name:
            flash("Project name is required.", "danger")
            return redirect(url_for("projects.new"))

        project = Project(
            user_id=current_user.id,
            name=name,
            description=description,
            excluded_dirs=custom_exclusions or "node_modules,.git,.venv,venv,__pycache__,dist,build,coverage,vendor"
        )
        db.session.add(project)
        db.session.flush()

        if upload and upload.filename:
            if not upload.filename.lower().endswith(".zip"):
                db.session.rollback()
                flash("Please upload a standard ZIP archive (.zip).", "danger")
                return redirect(url_for("projects.new"))
            try:
                storage_root = current_app.config["UPLOAD_FOLDER"]
                target_dir, primary_language, file_count, total_size, lang_breakdown = safe_extract_archive(
                    upload, project.id, storage_root, custom_exclusions=project.excluded_dirs
                )
                project.source_path = target_dir
                project.archive_filename = upload.filename
                project.language = primary_language
                project.file_count = file_count
                project.total_size_bytes = total_size
            except ValueError as exc:
                db.session.rollback()
                flash(f"Extraction Error: {str(exc)}", "danger")
                return redirect(url_for("projects.new"))

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="create_project",
            resource_type="project",
            resource_id=str(project.id),
            details=f"Created project {name} with {project.file_count} files."
        ))
        db.session.commit()
        flash(f"Repository '{name}' registered successfully.", "success")
        return redirect(url_for("projects.detail", project_id=project.id))

    return render_template("project_new.html")

@projects_bp.route("/<int:project_id>")
@login_required
def detail(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    scans = Scan.query.filter_by(project_id=project.id).order_by(Scan.created_at.desc()).all()
    
    # Calculate language breakdown
    files = ProjectFile.query.filter_by(project_id=project.id).all()
    lang_counts = {}
    for f in files:
        lang_counts[f.language] = lang_counts.get(f.language, 0) + 1

    # Findings summary for latest scan
    latest_scan = project.latest_scan
    latest_findings = latest_scan.findings if latest_scan else []
    
    # Tree structure for repository explorer
    tree_nodes = get_repository_tree(project.id)

    return render_template(
        "project_detail.html",
        project=project,
        scans=scans,
        latest_scan=latest_scan,
        latest_findings=latest_findings[:15],
        lang_counts=lang_counts,
        tree_nodes=tree_nodes,
        total_files=len(files)
    )

@projects_bp.route("/<int:project_id>/update", methods=["POST"])
@login_required
def update(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    excluded_dirs = request.form.get("excluded_dirs", "").strip()

    if name:
        project.name = name
    project.description = description
    project.excluded_dirs = excluded_dirs
    db.session.commit()
    flash("Repository settings updated.", "success")
    return redirect(url_for("projects.detail", project_id=project.id))

@projects_bp.route("/<int:project_id>/delete", methods=["POST"])
@login_required
def delete(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    p_name = project.name
    db.session.delete(project)
    db.session.add(AuditLog(
        user_id=current_user.id,
        action="delete_project",
        resource_type="project",
        resource_id=str(project_id),
        details=f"Deleted project {p_name}"
    ))
    db.session.commit()
    flash(f"Repository '{p_name}' deleted.", "success")
    return redirect(url_for("projects.index"))

@projects_bp.route("/<int:project_id>/tree")
@login_required
def tree(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    tree_data = get_repository_tree(project.id)
    return jsonify(tree_data)
