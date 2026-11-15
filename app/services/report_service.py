import csv
import json
from pathlib import Path
from datetime import datetime, timezone
from flask import current_app
from extensions import db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.project import Project
from app.models.report import Report
from app.models.project_file import ProjectFile
from app.models.risk_assessment import RiskAssessment

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def ensure_reports_dir():
    folder = Path(current_app.config.get("REPORTS_FOLDER", "storage/reports")).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def generate_csv_report(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    project = scan.project
    reports_dir = ensure_reports_dir()
    
    filename = f"ForgeGuard_Report_{project.name.replace(' ', '_')}_Scan_{scan.id}.csv"
    filepath = reports_dir / filename

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Finding ID", "Project", "Scan ID", "Rule ID", "Category", "Severity",
            "Confidence", "File Path", "Line", "Column", "Title", "Description",
            "Technical Explanation", "Why It Matters", "Recommendation", "Suggested Fix",
            "Status", "Detection Tool"
        ])
        for item in scan.findings:
            writer.writerow([
                item.id, project.name, scan.id, item.rule_id, item.category, item.severity,
                item.confidence, item.file_path, item.line_number or "", item.column_number or "",
                item.title, item.description, item.technical_explanation, item.why_it_matters,
                item.recommendation, item.suggested_fix, item.status, item.detection_tool
            ])

    # Save Report record in DB
    rep = Report(
        scan_id=scan.id,
        project_id=project.id,
        user_id=project.user_id,
        report_format="csv",
        file_name=filename,
        file_path=str(filepath),
        file_size_bytes=filepath.stat().st_size
    )
    db.session.add(rep)
    db.session.commit()
    return rep


def generate_json_report(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    project = scan.project
    reports_dir = ensure_reports_dir()

    filename = f"ForgeGuard_Report_{project.name.replace(' ', '_')}_Scan_{scan.id}.json"
    filepath = reports_dir / filename

    data = {
        "platform": "ForgeGuard AI — Intelligent Software Engineering Platform",
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "language": project.language,
            "total_files": project.file_count,
            "total_size_bytes": project.total_size_bytes
        },
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "files_scanned": scan.files_scanned,
            "files_skipped": scan.files_skipped,
            "findings_count": scan.findings_count,
            "risk_score": scan.risk_score,
            "health_score": scan.health_score,
            "health_label": scan.health_label,
            "security_score": scan.security_score,
            "quality_score": scan.quality_score,
            "dependency_score": scan.dependency_score,
            "maintainability_score": scan.maintainability_score
        },
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "column_number": f.column_number,
                "title": f.title,
                "description": f.description,
                "technical_explanation": f.technical_explanation,
                "why_it_matters": f.why_it_matters,
                "recommendation": f.recommendation,
                "suggested_fix": f.suggested_fix,
                "detection_tool": f.detection_tool,
                "status": f.status
            } for f in scan.findings
        ]
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    rep = Report(
        scan_id=scan.id,
        project_id=project.id,
        user_id=project.user_id,
        report_format="json",
        file_name=filename,
        file_path=str(filepath),
        file_size_bytes=filepath.stat().st_size
    )
    db.session.add(rep)
    db.session.commit()
    return rep


def generate_pdf_report(scan_id: int):
    scan = Scan.query.get_or_404(scan_id)
    project = scan.project
    reports_dir = ensure_reports_dir()

    filename = f"ForgeGuard_Executive_Report_{project.name.replace(' ', '_')}_Scan_{scan.id}.pdf"
    filepath = reports_dir / filename

    if not REPORTLAB_AVAILABLE:
        # Fallback to generating text/html if reportlab is absent
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"ForgeGuard AI Security & Quality Report\nProject: {project.name}\nHealth Score: {scan.health_score}/100\nTotal Findings: {scan.findings_count}")
        rep = Report(
            scan_id=scan.id,
            project_id=project.id,
            user_id=project.user_id,
            report_format="pdf",
            file_name=filename,
            file_path=str(filepath),
            file_size_bytes=filepath.stat().st_size
        )
        db.session.add(rep)
        db.session.commit()
        return rep

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=10
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#475569"),
        spaceAfter=20
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=15,
        spaceAfter=10
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("ForgeGuard AI — Repository Intelligence Report", title_style))
    story.append(Paragraph(f"Project: <b>{project.name}</b> | Generated: {datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')}", subtitle_style))
    story.append(Spacer(1, 10))

    # Executive Summary Box
    summary_data = [
        ["Overall Health Score", f"{scan.health_score}/100 ({scan.health_label})", "Total Findings", str(scan.findings_count)],
        ["Security Score", f"{scan.security_score}/100", "Critical Issues", str(scan.critical_count)],
        ["Quality Score", f"{scan.quality_score}/100", "High Severity", str(scan.high_count)],
        ["Dependency Score", f"{scan.dependency_score}/100", "Medium Severity", str(scan.medium_count)],
        ["Files Analyzed", str(scan.files_scanned), "Low / Info Severity", str(scan.low_count + scan.info_count)]
    ]
    summary_table = Table(summary_data, colWidths=[130, 130, 130, 130])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1"))
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Findings Table (Top Priority)
    story.append(Paragraph("Key Findings & Security Vulnerabilities", section_heading))
    findings_data = [["Sev", "Rule ID", "Location", "Title & Remediation Summary"]]
    
    # Priority sorting: Critical -> High -> Medium -> Low
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(scan.findings, key=lambda x: sev_order.get(x.severity.lower(), 5))[:25]

    for item in sorted_findings:
        sev_color = colors.HexColor("#EF4444") if item.severity.lower() == "critical" else (
            colors.HexColor("#F97316") if item.severity.lower() == "high" else (
                colors.HexColor("#F59E0B") if item.severity.lower() == "medium" else colors.HexColor("#3B82F6")
            )
        )
        findings_data.append([
            item.severity.upper()[:4],
            item.rule_id[:16],
            f"{item.file_path[:22]}:{item.line_number or ''}",
            Paragraph(f"<b>{item.title}</b><br/>{item.recommendation[:120]}", body_style)
        ])

    if len(findings_data) > 1:
        findings_table = Table(findings_data, colWidths=[45, 95, 110, 270])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        story.append(findings_table)
    else:
        story.append(Paragraph("No critical or high issues detected.", body_style))

    story.append(Spacer(1, 25))
    story.append(Paragraph("Remediation Roadmap", section_heading))
    story.append(Paragraph(
        "1. Immediately revoke and rotate any leaked secrets or tokens detected in source control.<br/>"
        "2. Replace direct string interpolation in SQL and system commands with parameterized statements.<br/>"
        "3. Upgrade vulnerable packages to the fixed versions indicated in the Dependency Analysis report.<br/>"
        "4. Refactor functions with high cyclomatic complexity (CC >= 10) to improve maintainability and testability.",
        body_style
    ))

    doc.build(story)

    rep = Report(
        scan_id=scan.id,
        project_id=project.id,
        user_id=project.user_id,
        report_format="pdf",
        file_name=filename,
        file_path=str(filepath),
        file_size_bytes=filepath.stat().st_size
    )
    db.session.add(rep)
    db.session.commit()
    return rep
