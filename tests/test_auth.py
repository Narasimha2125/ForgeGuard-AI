from app.models.user import User
from extensions import db

def test_register_success(client):
    res = client.post("/register", data={
        "name": "Jane Doe",
        "email": "jane@example.com",
        "password": "SecurePassword123!"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Platform Overview" in res.data

def test_duplicate_registration_fails(client):
    client.post("/register", data={
        "name": "Jane Doe",
        "email": "jane@example.com",
        "password": "SecurePassword123!"
    })
    client.get("/logout")
    res = client.post("/register", data={
        "name": "Jane Two",
        "email": "jane@example.com",
        "password": "SecurePassword123!"
    }, follow_redirects=True)
    assert b"already exists" in res.data

def test_login_and_logout(client):
    client.post("/register", data={
        "name": "Alex Smith",
        "email": "alex@example.com",
        "password": "Password12345!"
    })
    # Logout
    res_logout = client.get("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"Sign In to Platform" in res_logout.data

    # Login
    res_login = client.post("/login", data={
        "email": "alex@example.com",
        "password": "Password12345!"
    }, follow_redirects=True)
    assert b"Platform Overview" in res_login.data
