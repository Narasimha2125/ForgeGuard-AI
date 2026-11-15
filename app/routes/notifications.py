from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from extensions import db
from app.models.notification import Notification

notifications_bp = Blueprint("notifications", __name__)

@notifications_bp.route("/notifications")
@login_required
def index():
    filter_type = request.args.get("type", "").strip()
    query = Notification.query.filter_by(user_id=current_user.id)
    if filter_type:
        query = query.filter_by(notification_type=filter_type)
    
    notifications = query.order_by(Notification.created_at.desc()).all()
    unread_count = sum(1 for n in notifications if not n.is_read)

    return render_template(
        "notifications.html",
        notifications=notifications,
        unread_count=unread_count,
        filter_type=filter_type
    )

@notifications_bp.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_read(notification_id):
    notif = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    notif.is_read = True
    db.session.commit()
    return redirect(request.referrer or url_for("notifications.index"))

@notifications_bp.route("/notifications/read-all", methods=["POST"])
@login_required
def mark_all_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications.index"))

@notifications_bp.route("/notifications/<int:notification_id>/delete", methods=["POST"])
@login_required
def delete(notification_id):
    notif = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    db.session.delete(notif)
    db.session.commit()
    return redirect(request.referrer or url_for("notifications.index"))

@notifications_bp.route("/api/notifications/unread-count")
@login_required
def unread_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    recent = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    return jsonify({
        "count": count,
        "recent": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message[:80],
                "severity": n.severity,
                "time": n.created_at.strftime("%H:%M") if n.created_at else "",
                "link": n.link_url or "#"
            } for n in recent
        ]
    })
