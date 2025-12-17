import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.db.session import get_db
from app.models.base import Base

# Use a separate test database (SQLite for simplicity)
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def admin_user(db_session):
    from app.models.user import User, UserRole
    from app.core.security import get_password_hash
    user = User(
        email="admin@example.com",
        username="admin",
        hashed_password=get_password_hash("adminpass"),
        role=UserRole.ADMIN,
        is_active=True,
        full_name="Admin User"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user.id  # Return ID instead of object to avoid session issues

@pytest.fixture
def analyst_user(db_session):
    from app.models.user import User, UserRole
    from app.core.security import get_password_hash
    user = User(
        email="analyst@example.com",
        username="analyst",
        hashed_password=get_password_hash("analystpass"),
        role=UserRole.ANALYST,
        is_active=True,
        full_name="Analyst User"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user.id  # Return ID instead of object to avoid session issues

@pytest.fixture
def viewer_user(db_session):
    from app.models.user import User, UserRole
    from app.core.security import get_password_hash
    user = User(
        email="viewer@example.com",
        username="viewer",
        hashed_password=get_password_hash("viewerpass"),
        role=UserRole.VIEWER,
        is_active=True,
        full_name="Viewer User"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user.id  # Return ID instead of object to avoid session issues

def auth_headers(username: str, password: str, client: TestClient):
    response = client.post("/api/auth/token", data={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_token(client, admin_user):
    return auth_headers("admin", "adminpass", client)

@pytest.fixture
def analyst_token(client, analyst_user):
    return auth_headers("analyst", "analystpass", client)

@pytest.fixture
def viewer_token(client, viewer_user):
    return auth_headers("viewer", "viewerpass", client)
