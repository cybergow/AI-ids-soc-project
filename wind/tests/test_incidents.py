def test_list_incidents_as_viewer(client, viewer_token):
    response = client.get("/api/incidents/", headers=viewer_token)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_create_incident_as_analyst(client, analyst_token):
    payload = {
        "title": "Test Incident",
        "description": "Incident created by test",
        "type": "malware",
        "status": "open",
        "severity": "medium"
    }
    response = client.post("/api/incidents/", json=payload, headers=analyst_token)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    incident_id = data["id"]
    return incident_id

def test_create_incident_as_viewer_forbidden(client, viewer_token):
    payload = {
        "title": "Forbidden Incident",
        "description": "Should not be created",
        "type": "malware",
        "status": "open",
        "severity": "medium"
    }
    response = client.post("/api/incidents/", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_get_incident_by_id(client, analyst_token):
    incident_id = test_create_incident_as_analyst(client, analyst_token)
    response = client.get(f"/api/incidents/{incident_id}", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == incident_id

def test_get_incident_by_id_not_found(client, analyst_token):
    response = client.get("/api/incidents/99999", headers=analyst_token)
    assert response.status_code == 404

def test_update_incident_as_analyst(client, analyst_token):
    incident_id = test_create_incident_as_analyst(client, analyst_token)
    payload = {"status": "contained", "severity": "low"}
    response = client.put(f"/api/incidents/{incident_id}", json=payload, headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == payload["status"]
    assert data["severity"] == payload["severity"]

def test_update_incident_as_viewer_forbidden(client, analyst_token, viewer_token):
    incident_id = test_create_incident_as_analyst(client, analyst_token)
    payload = {"status": "contained"}
    response = client.put(f"/api/incidents/{incident_id}", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_delete_incident_as_analyst(client, analyst_token):
    incident_id = test_create_incident_as_analyst(client, analyst_token)
    response = client.delete(f"/api/incidents/{incident_id}", headers=analyst_token)
    assert response.status_code == 204

def test_delete_incident_as_viewer_forbidden(client, analyst_token, viewer_token):
    incident_id = test_create_incident_as_analyst(client, analyst_token)
    response = client.delete(f"/api/incidents/{incident_id}", headers=viewer_token)
    assert response.status_code == 403

def test_incidents_filtering(client, analyst_token):
    # Create two incidents with different severities
    for severity in ["low", "critical"]:
        payload = {
            "title": f"Incident {severity}",
            "description": "Test incident for filtering",
            "type": "malware",
            "status": "open",
            "severity": severity
        }
        client.post("/api/incidents/", json=payload, headers=analyst_token)
    # Filter by severity=critical
    response = client.get("/api/incidents/?severity=critical", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    for incident in data:
        assert incident["severity"] == "critical"
