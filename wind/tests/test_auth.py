def test_register_user(client):
    payload = {
        "email": "newuser@example.com",
        "username": "newuser",
        "password": "NewPass123!",
        "full_name": "New User",
        "is_active": True,
        "role": "viewer"
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]
    assert data["username"] == payload["username"]
    assert "id" in data

def test_login_for_access_token(client, admin_user):
    response = client.post("/api/auth/token", data={"username": "admin", "password": "adminpass"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_read_users_me(client, admin_user):
    # First login
    response = client.post("/api/auth/token", data={"username": "admin", "password": "adminpass"})
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    # Then get current user
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
    assert data["email"] == "admin@example.com"

def test_invalid_token(client):
    headers = {"Authorization": "Bearer invalidtoken"}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
