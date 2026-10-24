import importlib
import pytest

@pytest.fixture()
def app(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    uploads = data_dir / "private_uploads"
    db_path = data_dir / "test.sqlite3"
    monkeypatch.setenv("SECUREDOCS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_USER", "admin")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "AdminPassword-123!")
    import app as app_module
    # The module may already have been imported by another test; reload after env setup.
    importlib.reload(app_module)
    app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield app_module.app
    app_module.app.config["TESTING"] = False

@pytest.fixture()
def client(app):
    return app.test_client()

def csrf(client):
    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")

def register(client, username, password="StrongPassword-123!"):
    return client.post("/register", data={"username": username, "password": password}, follow_redirects=True)

def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
