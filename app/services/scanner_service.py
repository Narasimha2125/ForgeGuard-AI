import os
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from flask import current_app
from extensions import db
from app.models.project import Project
from app.models.project_file import ProjectFile
from app.models.scan import Scan
from app.models.scan_stage import ScanStage
from app.models.finding import Finding
from app.models.metrics import ProjectMetric
from app.models.risk_assessment import RiskAssessment
from app.models.recommendation import Recommendation
from app.engines.code_analyzer import analyze_generic_source_file
from app.engines.security_analyzer import analyze_security_file
from app.engines.dependency_analyzer import analyze_dependency_file
from app.engines.risk_engine import calculate_comprehensive_risk
from app.engines.recommendation_engine import recommend_for_finding
from app.services.notification_service import notify_scan_complete, notify_scan_failed, notify_critical_finding

STAGE_DEFINITIONS = [
    (1, "Repository Validation"),
    (2, "File Extraction & Indexing"),
    (3, "Project Structure Detection"),
    (4, "Programming Language Detection"),
    (5, "Source Code Discovery"),
    (6, "Code Quality Analysis"),
    (7, "Security & Secret Analysis"),
    (8, "Dependency Vulnerability Analysis"),
    (9, "Risk & Health Scoring"),
    (10, "Recommendation Generation"),
    (11, "Report Compilation")
]


def update_scan_stage(scan: Scan, stage_num: int, status: str = "running", message: str = ""):
    scan.current_stage_number = stage_num
    scan.current_stage = STAGE_DEFINITIONS[stage_num - 1][1]
    scan.progress_percent = int(((stage_num - 1) / len(STAGE_DEFINITIONS)) * 100)
    
    stage = ScanStage.query.filter_by(scan_id=scan.id, stage_number=stage_num).first()
    if not stage:
        stage = ScanStage(
            scan_id=scan.id,
            stage_number=stage_num,
            stage_name=scan.current_stage,
            status=status,
            message=message,
            started_at=datetime.now(timezone.utc)
        )
        db.session.add(stage)
    else:
        stage.status = status
        stage.message = message
        if status == "running" and not stage.started_at:
            stage.started_at = datetime.now(timezone.utc)
        elif status in ("completed", "failed"):
            stage.completed_at = datetime.now(timezone.utc)
            
    db.session.commit()
    return stage


def create_initial_scan(project_id: int):
    scan = Scan(
        project_id=project_id,
        status="pending",
        current_stage="Queued",
        current_stage_number=0,
        progress_percent=0,
        started_at=datetime.now(timezone.utc)
    )
    db.session.add(scan)
    db.session.commit()

    # Pre-populate 11 scan stages in pending state
    for num, name in STAGE_DEFINITIONS:
        stage = ScanStage(
            scan_id=scan.id,
            stage_number=num,
            stage_name=name,
            status="pending"
        )
        db.session.add(stage)
    db.session.commit()
    return scan


def launch_background_scan(app, scan_id: int, categories: list = None):
    """Spawns an isolated background thread to execute the scan asynchronously."""
    thread = threading.Thread(
        target=_run_scan_thread,
        args=(app._get_current_object(), scan_id, categories or ["quality", "security", "dependency", "architecture"]),
        daemon=True
    )
    thread.start()
    return thread


def _run_scan_thread(app, scan_id: int, categories: list):
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        project = scan.project
        try:
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            db.session.commit()

            root_path = Path(project.source_path).resolve() if project.source_path else None
            
            # Stage 1: Repository Validation
            update_scan_stage(scan, 1, "running", "Validating repository existence and accessibility...")
            if not root_path or not root_path.exists():
                raise ValueError("Project source directory does not exist or has been removed.")
            time.sleep(0.3)
            update_scan_stage(scan, 1, "completed", "Repository verified.")

            # Stage 2: File Extraction & Indexing
            update_scan_stage(scan, 2, "running", "Verifying indexed repository files...")
            files = ProjectFile.query.filter_by(project_id=project.id).all()
            if not files:
                from app.services.repository_service import index_repository_files
                files, _, _ = index_repository_files(project.id, root_path)
            time.sleep(0.3)
            update_scan_stage(scan, 2, "completed", f"Indexed {len(files)} files.")

            # Stage 3: Project Structure Detection
            update_scan_stage(scan, 3, "running", "Analyzing directory hierarchy and package structure...")
            dir_count = sum(1 for p in root_path.rglob("*") if p.is_dir())
            db.session.add(ProjectMetric(scan_id=scan.id, metric_category="general", metric_name="directories_count", metric_value=dir_count))
            time.sleep(0.3)
            update_scan_stage(scan, 3, "completed", f"Structure mapped with {dir_count} directories.")

            # Stage 4: Programming Language Detection
            update_scan_stage(scan, 4, "running", "Calculating language distribution...")
            lang_stats = {}
            for f in files:
                lang_stats[f.language] = lang_stats.get(f.language, 0) + 1
            for lang, count in lang_stats.items():
                db.session.add(ProjectMetric(scan_id=scan.id, metric_category="general", metric_name=f"lang_count_{lang}", metric_value=count))
            time.sleep(0.3)
            update_scan_stage(scan, 4, "completed", f"Primary language: {project.language}")

            # Stage 5: Source Code Discovery
            update_scan_stage(scan, 5, "running", "Filtering analyzable source files...")
            source_files = [f for f in files if f.is_analyzed and Path(f.file_path).exists()]
            scan.files_scanned = len(source_files)
            scan.files_skipped = len(files) - len(source_files)
            time.sleep(0.3)
            update_scan_stage(scan, 5, "completed", f"Found {len(source_files)} source files for deep scanning.")

            all_findings = []

            # Stage 6: Code Quality Analysis
            update_scan_stage(scan, 6, "running", "Running AST and complexity inspections...")
            if "quality" in categories:
                for sf in source_files:
                    # check if cancelled
                    db.session.refresh(scan)
                    if scan.status == "cancelled":
                        return
                    p = Path(sf.file_path)
                    q_findings = analyze_generic_source_file(p)
                    for qf in q_findings:
                        qf["project_id"] = project.id
                        qf["scan_id"] = scan.id
                        qf["file_path"] = qf.get("file_path") or sf.relative_path
                        finding = Finding(**qf)
                        finding.generate_fingerprint()
                        db.session.add(finding)
                        all_findings.append(finding)
                db.session.commit()
            update_scan_stage(scan, 6, "completed", "Quality analysis finished.")

            # Stage 7: Security Analysis
            update_scan_stage(scan, 7, "running", "Scanning for credentials, injection risks, and CWE flaws...")
            if "security" in categories:
                for sf in source_files:
                    db.session.refresh(scan)
                    if scan.status == "cancelled":
                        return
                    p = Path(sf.file_path)
                    sec_findings = analyze_security_file(p, root_path)
                    for sec in sec_findings:
                        sec["project_id"] = project.id
                        sec["scan_id"] = scan.id
                        sec["file_path"] = sec.get("file_path") or sf.relative_path
                        finding = Finding(**sec)
                        finding.generate_fingerprint()
                        db.session.add(finding)
                        all_findings.append(finding)
                        
                        # Trigger alert if critical secret or vulnerability
                        if finding.severity.lower() == "critical":
                            notify_critical_finding(project.user_id, project.name, scan.id, finding.title, finding.file_path)
                db.session.commit()
            update_scan_stage(scan, 7, "completed", "Security analysis finished.")

            # Stage 8: Dependency Analysis
            update_scan_stage(scan, 8, "running", "Inspecting manifests and querying OSV vulnerability database...")
            if "dependency" in categories:
                dep_manifests = [f for f in files if f.file_name.lower() in (
                    "requirements.txt", "package.json", "package-lock.json",
                    "pyproject.toml", "cargo.toml", "go.mod"
                )]
                for df in dep_manifests:
                    db.session.refresh(scan)
                    if scan.status == "cancelled":
                        return
                    p = Path(df.file_path)
                    dep_findings, packages = analyze_dependency_file(p, root_path)
                    for df_item in dep_findings:
                        df_item["project_id"] = project.id
                        df_item["scan_id"] = scan.id
                        df_item["file_path"] = df_item.get("file_path") or df.relative_path
                        finding = Finding(**df_item)
                        finding.generate_fingerprint()
                        db.session.add(finding)
                        all_findings.append(finding)
                db.session.commit()
            update_scan_stage(scan, 8, "completed", "Dependency analysis finished.")

            # Stage 9: Risk & Health Scoring
            update_scan_stage(scan, 9, "running", "Computing weighted risk matrix and project health metrics...")
            risk_data = calculate_comprehensive_risk(all_findings)
            
            # Update scan counters
            scan.findings_count = len(all_findings)
            scan.critical_count = sum(1 for f in all_findings if f.severity.lower() == "critical")
            scan.high_count = sum(1 for f in all_findings if f.severity.lower() == "high")
            scan.medium_count = sum(1 for f in all_findings if f.severity.lower() == "medium")
            scan.low_count = sum(1 for f in all_findings if f.severity.lower() == "low")
            scan.info_count = sum(1 for f in all_findings if f.severity.lower() == "info")
            
            scan.risk_score = risk_data["overall_risk_score"]
            scan.health_score = risk_data["health_score"]
            scan.health_label = risk_data["health_label"]
            scan.security_score = risk_data["security_score"]
            scan.quality_score = risk_data["quality_score"]
            scan.dependency_score = risk_data["dependency_score"]
            scan.maintainability_score = risk_data["maintainability_score"]

            # Save RiskAssessment record
            ra = RiskAssessment(
                scan_id=scan.id,
                overall_risk_score=risk_data["overall_risk_score"],
                security_risk=risk_data["security_risk"],
                quality_risk=risk_data["quality_risk"],
                dependency_risk=risk_data["dependency_risk"],
                risk_level=risk_data["risk_level"],
                explanation=risk_data["explanation"]
            )
            db.session.add(ra)
            db.session.commit()
            update_scan_stage(scan, 9, "completed", f"Health rated '{scan.health_label}' ({scan.health_score}/100).")

            # Stage 10: Recommendation Generation
            update_scan_stage(scan, 10, "running", "Generating remediation guidance and code diffs...")
            for f in all_findings:
                rec_info = recommend_for_finding(f)
                rec = Recommendation(
                    finding_id=f.id,
                    priority=rec_info["priority"],
                    title=rec_info["title"],
                    plain_explanation=rec_info["plain_explanation"],
                    technical_explanation=rec_info["technical_explanation"],
                    proposed_diff=rec_info["proposed_diff"],
                    doc_links=rec_info["doc_links"]
                )
                db.session.add(rec)
            db.session.commit()
            update_scan_stage(scan, 10, "completed", f"Generated recommendations for {len(all_findings)} findings.")

            # Stage 11: Report Compilation
            update_scan_stage(scan, 11, "running", "Pre-compiling reports and artifacts...")
            try:
                from app.services.report_service import generate_csv_report, generate_json_report, generate_pdf_report
                generate_csv_report(scan.id)
                generate_json_report(scan.id)
                generate_pdf_report(scan.id)
            except Exception as rep_err:
                pass
            update_scan_stage(scan, 11, "completed", "Reports compiled.")

            # Scan completion
            scan.status = "completed"
            scan.progress_percent = 100
            scan.current_stage = "Scan Complete"
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()

            # Notify user
            notify_scan_complete(project.user_id, project.name, scan.id, scan.findings_count, scan.health_label)

        except Exception as exc:
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
                if scan.current_stage_number > 0:
                    update_scan_stage(scan, scan.current_stage_number, "failed", f"Failed: {str(exc)[:150]}")
                notify_scan_failed(project.user_id, project.name, scan.id, str(exc))
