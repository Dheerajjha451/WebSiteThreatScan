from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client():
    return create_app({"TESTING": True, "SCANNER_API_KEY": ""}).test_client()


@pytest.mark.parametrize("body", [None, [], "text", 5, {}, {"url": "https://example.com"}, {"url": "https://example.com", "authorized": "true"}])
def test_malformed_body_never_starts_scan(client, body):
    with patch("app.WebSecurityScanner.scan") as scan:
        response = client.post("/scan", json=body, content_type="application/json")
    assert response.status_code == 400
    scan.assert_not_called()


@pytest.mark.parametrize("options", [{"max_urls": True}, {"max_urls": 21}, {"max_depth": -1}, {"max_depth": 1.5}, {"unknown": 1}, {"url": "http://127.0.0.1/"}])
def test_rejects_invalid_scan_options(client, options):
    body = dict(url="https://example.com", authorized=True)
    body.update(options)
    with patch("app.WebSecurityScanner.scan") as scan:
        response = client.post("/scan", json=body)
    assert response.status_code == 400
    scan.assert_not_called()


def test_content_type_and_size_limit(client):
    assert client.post("/scan", data="x").status_code == 415
    assert client.post("/scan", data="{" + "x" * 9000, content_type="application/json").status_code == 413
    assert client.post("/scan", data="{", content_type="application/json").status_code == 400


def test_auth_and_security_headers():
    client = create_app({"TESTING": True, "SCANNER_API_KEY": "PRIVATE"}).test_client()
    assert client.post("/scan", json={}).status_code == 401
    assert client.post("/scan", json={}, headers={"Authorization": "Bearer WRONG"}).status_code == 401
    assert client.post("/scan", json={}, headers={"Authorization": "Bearer PRIVATE"}).status_code == 400
    response = client.get("/health", headers={"Origin": "https://evil.example"})
    assert response.json["status"] == "ok"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in response.headers


def test_partial_report_and_rate_limit(client):
    with patch("app.WebSecurityScanner.scan", return_value={"scanned_urls": [], "warnings": []}):
        for _ in range(5):
            assert client.post("/scan", json={"url": "https://example.com", "authorized": True}).status_code == 422
        response = client.post("/scan", json={"url": "https://example.com", "authorized": True}, headers={"X-Forwarded-For": "8.8.8.8"})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"


def test_capacity_limit_and_failure_release_slots(client):
    guard = client.application.extensions["scan_guard"]
    guard.slots.acquire()
    guard.slots.acquire()
    response = client.post("/scan", json={"url": "https://example.com", "authorized": True})
    assert response.status_code == 503
    guard.slots.release()
    guard.slots.release()
    with patch("app.WebSecurityScanner.scan", side_effect=RuntimeError("PRIVATE_INTERNAL_DETAILS")):
        response = client.post("/scan", json={"url": "https://example.com", "authorized": True})
    assert response.status_code == 500
    assert "PRIVATE_INTERNAL_DETAILS" not in response.text
    assert guard.slots.acquire(blocking=False)
    guard.slots.release()
