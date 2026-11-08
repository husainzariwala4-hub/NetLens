from fastapi.testclient import TestClient

from netlens.capture import CaptureService
from netlens.main import create_app


def test_local_api_and_validation(monkeypatch):
    monkeypatch.setattr("netlens.capture.get_if_list", lambda: ["eth-test"])
    app = create_app(CaptureService(set()))
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 5000)) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        assert client.get("/api/interfaces").json() == {"interfaces": [{"name": "eth-test", "allowed": False}]}
        assert client.post("/api/capture/start", json={"interface": "eth-test"}).status_code == 409
        assert client.post("/api/capture/start", json={"interface": ""}).status_code == 422
        assert client.get("/api/packets?limit=501").status_code == 422
        assert client.get("/api/packets").json()["items"] == []
        assert client.get("/api/health", headers={"origin": "https://evil.example"}).status_code == 403
        assert client.get("/api/health", headers={"host": "evil.example"}).status_code == 403


def test_remote_peer_denied():
    app = create_app(CaptureService(set()))
    with TestClient(app, base_url="http://127.0.0.1", client=("192.0.2.10", 5000)) as client:
        assert client.get("/api/health").status_code == 403
