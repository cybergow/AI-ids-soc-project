def test_list_models_as_viewer(client, viewer_token):
    response = client.get("/api/models/", headers=viewer_token)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_register_model_as_analyst(client, analyst_token):
    payload = {
        "name": "TestModel",
        "version": "1.0.0",
        "description": "Model created by test",
        "model_type": "classification",
        "status": "training",
        "is_active": True,
        "metadata_json": "{\"accuracy\": 0.95}"
    }
    response = client.post("/api/models/", json=payload, headers=analyst_token)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == payload["name"]
    model_id = data["id"]
    return model_id

def test_register_model_as_viewer_forbidden(client, viewer_token):
    payload = {
        "name": "ForbiddenModel",
        "version": "1.0.0",
        "description": "Should not be created",
        "model_type": "classification",
        "status": "training",
        "is_active": True
    }
    response = client.post("/api/models/", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_get_model_by_id(client, analyst_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    response = client.get(f"/api/models/{model_id}", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == model_id

def test_get_model_by_id_not_found(client, analyst_token):
    response = client.get("/api/models/99999", headers=analyst_token)
    assert response.status_code == 404

def test_update_model_as_analyst(client, analyst_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    payload = {"status": "ready", "is_active": False}
    response = client.put(f"/api/models/{model_id}", json=payload, headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == payload["status"]
    assert data["is_active"] == payload["is_active"]

def test_update_model_as_viewer_forbidden(client, analyst_token, viewer_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    payload = {"status": "ready"}
    response = client.put(f"/api/models/{model_id}", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_delete_model_as_analyst(client, analyst_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    response = client.delete(f"/api/models/{model_id}", headers=analyst_token)
    assert response.status_code == 204

def test_delete_model_as_viewer_forbidden(client, analyst_token, viewer_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    response = client.delete(f"/api/models/{model_id}", headers=viewer_token)
    assert response.status_code == 403

def test_retrain_model_as_analyst(client, analyst_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    payload = {"parameters": {"epochs": 10}}
    response = client.post(f"/api/models/{model_id}/retrain", json=payload, headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["model_id"] == model_id
    assert "message" in data

def test_retrain_model_as_viewer_forbidden(client, analyst_token, viewer_token):
    model_id = test_register_model_as_analyst(client, analyst_token)
    response = client.post(f"/api/models/{model_id}/retrain", headers=viewer_token)
    assert response.status_code == 403

def test_models_filtering(client, analyst_token):
    # Create two models with different statuses
    for status in ["training", "ready"]:
        payload = {
            "name": f"Model{status.capitalize()}",
            "version": "1.0.0",
            "description": "Test model for filtering",
            "model_type": "classification",
            "status": status,
            "is_active": True
        }
        client.post("/api/models/", json=payload, headers=analyst_token)
    # Filter by status=ready
    response = client.get("/api/models/?status=ready", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    for model in data:
        assert model["status"] == "ready"
