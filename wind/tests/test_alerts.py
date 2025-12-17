def test_list_alerts_as_viewer(client, viewer_token):
    response = client.get("/api/alerts/", headers=viewer_token)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_create_alert_as_analyst(client, analyst_token):
    payload = {
        "title": "Test Alert",
        "description": "Alert created by test",
        "type": "malware_detected",
        "status": "open",
        "severity": "medium",
        "source": "test"
    }
    response = client.post("/api/alerts/", json=payload, headers=analyst_token)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    alert_id = data["id"]
    return alert_id

def test_create_alert_as_viewer_forbidden(client, viewer_token):
    payload = {
        "title": "Forbidden Alert",
        "description": "Should not be created",
        "type": "malware_detected",
        "status": "open",
        "severity": "medium",
        "source": "test"
    }
    response = client.post("/api/alerts/", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_get_alert_by_id(client, analyst_token):
    alert_id = test_create_alert_as_analyst(client, analyst_token)
    response = client.get(f"/api/alerts/{alert_id}", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == alert_id

def test_get_alert_by_id_not_found(client, analyst_token):
    response = client.get("/api/alerts/99999", headers=analyst_token)
    assert response.status_code == 404

def test_update_alert_as_analyst(client, analyst_token):
    alert_id = test_create_alert_as_analyst(client, analyst_token)
    payload = {"status": "closed", "severity": "low"}
    response = client.put(f"/api/alerts/{alert_id}", json=payload, headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == payload["status"]
    assert data["severity"] == payload["severity"]

def test_update_alert_as_viewer_forbidden(client, analyst_token, viewer_token):
    alert_id = test_create_alert_as_analyst(client, analyst_token)
    payload = {"status": "closed"}
    response = client.put(f"/api/alerts/{alert_id}", json=payload, headers=viewer_token)
    assert response.status_code == 403

def test_delete_alert_as_analyst(client, analyst_token):
    alert_id = test_create_alert_as_analyst(client, analyst_token)
    response = client.delete(f"/api/alerts/{alert_id}", headers=analyst_token)
    assert response.status_code == 204

def test_delete_alert_as_viewer_forbidden(client, analyst_token, viewer_token):
    alert_id = test_create_alert_as_analyst(client, analyst_token)
    response = client.delete(f"/api/alerts/{alert_id}", headers=viewer_token)
    assert response.status_code == 403

def test_alerts_filtering(client, analyst_token):
    # Create two alerts with different severities
    for severity in ["low", "critical"]:
        payload = {
            "title": f"Alert {severity}",
            "description": "Test alert for filtering",
            "type": "malware_detected",
            "status": "open",
            "severity": severity,
            "source": "test"
        }
        client.post("/api/alerts/", json=payload, headers=analyst_token)
    # Filter by severity=low
    response = client.get("/api/alerts/?severity=low", headers=analyst_token)
    assert response.status_code == 200
    data = response.json()
    for alert in data:
        assert alert["severity"] == "low"
