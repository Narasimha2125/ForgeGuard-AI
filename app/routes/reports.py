from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from pathlib import Path
from extensions import db
from app.models.project import Project
from app.models.scan import Scan
from app.models.report import Report
from app.services.report_service import generate_csv_report, generate_json_report, generate_pdf_report

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]

    reports = Report.query.filter(Report.project_id.in_(project_ids)).order_by(Report.created_at.desc()).all() if project_ids else []
    completed_scans = Scan.query.filter(Scan.project_id.in_(project_ids), Scan.status == "completed").order_by(Scan.created_at.desc()).all() if project_ids else []

    return render_template(
        "reports.html",
        projects=projects,
        reports=reports,
        scans=completed_scans
    )

@reports_bp.route("/generate", methods=["POST"])
@login_required
def generate():
    scan_id = request.form.get("scan_id", type=int)
    fmt = request.form.get("format", "pdf").strip().lower()

    scan = Scan.query.get_or_404(scan_id)
    if scan.project.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("reports.index"))

    try:
        if fmt == "csv":
            rep = generate_csv_report(scan.id)
        elif fmt == "json":
            rep = generate_json_report(scan.id)
        else:
            rep = generate_pdf_report(scan.id)
        flash(f"{fmt.upper()} report generated successfully for Scan #{scan.id}.", "success")
        return redirect(url_for("reports.download", report_id=rep.id))
    except Exception as exc:
        flash(f"Report generation error: {str(exc)}", "danger")
        return redirect(url_for("reports.index"))

@reports_bp.route("/download/<int:report_id>")
@login_required
def download(report_id):
    rep = Report.query.get_or_404(report_id)
    if rep.project.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("reports.index"))

    file_path = Path(rep.file_path)
    if not file_path.exists():
        flash("Report file is missing on storage.", "danger")
        return redirect(url_for("reports.index"))

    return send_file(
        str(file_path),
        as_attachment=True,
        download_name=rep.file_name
    )
