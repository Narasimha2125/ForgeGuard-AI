from extensions import db
from app.models.notification import Notification

def create_notification(user_id: int, title: str, message: str, notification_type: str = "info", severity: str = "info", link_url: str = None):
    notif = Notification(
        user_id=user_id,
        title=title,
        message=message,
        notification_type=notification_type,
        severity=severity,
        link_url=link_url
    )
    db.session.add(notif)
    db.session.commit()
    return notif

def notify_scan_complete(user_id: int, project_name: str, scan_id: int, findings_count: int, health_label: str):
    create_notification(
        user_id=user_id,
        title=f"Scan Completed: {project_name}",
        message=f"Scan #{scan_id} finished. Detected {findings_count} findings. Project health rated '{health_label}'.",
        notification_type="scan_complete",
        severity="success" if health_label in ("Excellent", "Good") else "warning",
        link_url=f"/scans/{scan_id}"
    )

def notify_scan_failed(user_id: int, project_name: str, scan_id: int, error_msg: str):
    create_notification(
        user_id=user_id,
        title=f"Scan Failed: {project_name}",
        message=f"Scan #{scan_id} encountered an error: {error_msg[:120]}",
        notification_type="scan_failed",
        severity="danger",
        link_url=f"/scans/{scan_id}"
    )

def notify_critical_finding(user_id: int, project_name: str, scan_id: int, title: str, file_path: str):
    create_notification(
        user_id=user_id,
        title=f"Critical Security Alert: {project_name}",
        message=f"Critical issue '{title}' discovered in {file_path}.",
        notification_type="critical_finding",
        severity="danger",
        link_url=f"/findings?scan_id={scan_id}&severity=critical"
    )
