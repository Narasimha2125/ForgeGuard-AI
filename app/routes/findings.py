from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from extensions import db
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.audit_log import AuditLog

findings_bp = Blueprint("findings", __name__)

@findings_bp.route("/")
@login_required
def index():
    projects = Project.query.filter_by(user_id=current_user.id).order_by(Project.name).all()
    project_ids = [p.id for p in projects]

    selected_project_id = request.args.get("project_id", type=int)
    selected_scan_id = request.args.get("scan_id", type=int)
    severity_filter = request.args.get("severity", "").strip().lower()
    category_filter = request.args.get("category", "").strip().lower()
    status_filter = request.args.get("status", "").strip().lower()
    search_query = request.args.get("q", "").strip()

    target_project_ids = [selected_project_id] if selected_project_id else project_ids

    query = Finding.query.filter(Finding.project_id.in_(target_project_ids))

    if selected_scan_id:
        query = query.filter(Finding.scan_id == selected_scan_id)
    if severity_filter:
        query = query.filter(Finding.severity == severity_filter)
    if category_filter:
        query = query.filter(Finding.category == category_filter)
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    if search_query:
        query = query.filter(
            (Finding.title.ilike(f"%{search_query}%")) |
            (Finding.file_path.ilike(f"%{search_query}%")) |
            (Finding.rule_id.ilike(f"%{search_query}%")) |
            (Finding.description.ilike(f"%{search_query}%"))
        )

    findings = query.order_by(Finding.id.desc()).all()

    return render_template(
        "findings.html",
        projects=projects,
        selected_project_id=selected_project_id,
        selected_scan_id=selected_scan_id,
        severity_filter=severity_filter,
        category_filter=category_filter,
        status_filter=status_filter,
        search_query=search_query,
        findings=findings
    )

@findings_bp.route("/<int:finding_id>")
@login_required
def detail(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    scan = Scan.query.get(finding.scan_id)
    if scan.project.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    rec = finding.recommendations[0] if finding.recommendations else None
    return jsonify({
        "id": finding.id,
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "column_number": finding.column_number,
        "code_snippet": finding.code_snippet,
        "title": finding.title,
        "description": finding.description,
        "technical_explanation": finding.technical_explanation,
        "why_it_matters": finding.why_it_matters,
        "recommendation": finding.recommendation,
        "suggested_fix": finding.suggested_fix,
        "detection_tool": finding.detection_tool,
        "status": finding.status,
        "resolution_notes": finding.resolution_notes or "",
        "proposed_diff": rec.proposed_diff if rec else "",
        "doc_links": rec.doc_links if rec else ""
    })

@findings_bp.route("/<int:finding_id>/status", methods=["POST"])
@login_required
def update_status(finding_id):
    finding = Finding.query.get_or_404(finding_id)
    scan = Scan.query.get(finding.scan_id)
    if scan.project.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for("findings.index"))

    new_status = request.form.get("status", "open").strip().lower()
    notes = request.form.get("notes", "").strip()

    valid_statuses = {"open", "in_progress", "resolved", "accepted_risk", "false_positive", "ignored"}
    if new_status in valid_statuses:
        old_status = finding.status
        finding.status = new_status
        if notes:
            finding.resolution_notes = notes

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="update_finding_status",
            resource_type="finding",
            resource_id=str(finding.id),
            details=f"Status changed from {old_status} to {new_status}. Notes: {notes}"
        ))
        db.session.commit()
        flash(f"Finding #{finding.id} status updated to '{new_status}'.", "success")

    return redirect(request.referrer or url_for("findings.index"))
