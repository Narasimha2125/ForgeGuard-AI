from app.models.user import User
from app.models.notification import Notification
from extensions import db
from app.services.notification_service import create_notification

def test_notification_workflow(app, auth_client):
    with app.app_context():
        u = User.query.filter_by(email="dev@forgeguard.local").first()
        create_notification(u.id, "Test Alert", "A critical flaw was detected.", notification_type="critical_finding", severity="danger")
        assert Notification.query.filter_by(user_id=u.id, is_read=False).count() == 1

    # Check unread count endpoint
    res = auth_client.get("/api/notifications/unread-count")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] == 1

    # Mark all read
    auth_client.post("/notifications/read-all", follow_redirects=True)
    with app.app_context():
        u = User.query.filter_by(email="dev@forgeguard.local").first()
        assert Notification.query.filter_by(user_id=u.id, is_read=False).count() == 0
