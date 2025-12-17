def test_list_users_as_admin(client, admin_user, admin_token):
    response = client.get("/api/users/", headers=admin_token)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(u["id"] == admin_user for u in data)

def test_list_users_as_viewer(client, viewer_user, viewer_token):
    response = client.get("/api/users/", headers=viewer_token)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_create_user_as_admin(client, admin_token):
    payload = {
        "email": "created@example.com",
        "username": "created",
        "password": "Created123!",
        "full_name": "Created User",
        "is_active": True,
        "role": "viewer"
    }
    response = client.post("/api/users/", json=payload, headers=admin_token)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]

def test_create_user_as_viewer_forbidden(client, viewer_token):
    payload = {
        "email": "forbidden@example.com",
        "username": "forbidden",
        "password": "Forbidden123!",
        "full_name": "Forbidden User",
        "is_active": True,
        "role": "viewer"
    }
    response = client.post("/api/users/", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_get_user_by_id(client, admin_user, admin_token):
    response = client.get(f"/api/users/{admin_user}", headers=admin_token)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == admin_user

def test_get_user_by_id_not_found(client, admin_token):
    response = client.get("/api/users/99999", headers=admin_token)
    assert response.status_code == 404

def test_update_user_as_admin(client, admin_user, admin_token):
    payload = {"full_name": "Updated Admin"}
    response = client.put(f"/api/users/{admin_user}", json=payload, headers=admin_token)
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == payload["full_name"]

def test_update_user_as_viewer_forbidden(client, admin_user, viewer_token):
    payload = {"full_name": "Should Not Work"}
    response = client.put(f"/api/users/{admin_user}", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_delete_user_as_admin(client, admin_user, admin_token):
    response = client.delete(f"/api/users/{admin_user}", headers=admin_token)
    assert response.status_code == 204

def test_delete_user_as_viewer_forbidden(client, viewer_user, viewer_token):
    response = client.delete(f"/api/users/{viewer_user}", headers=viewer_token)
    assert response.status_code == 403
