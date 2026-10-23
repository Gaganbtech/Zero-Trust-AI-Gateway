import os, tempfile, pytest
from fastapi.testclient import TestClient
from app import config, audit
from app.main import app

@pytest.fixture()
def client(monkeypatch):
    tmp=tempfile.NamedTemporaryFile(suffix=".db",delete=False); tmp.close()
    monkeypatch.setattr(config.settings,"database_path",tmp.name)
    monkeypatch.setattr(audit.settings,"database_path",tmp.name)
    with TestClient(app) as c: yield c
    os.unlink(tmp.name)
