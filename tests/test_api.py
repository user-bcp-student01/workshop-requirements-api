import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
import pytest

from app.main import create_app


@pytest.fixture
def keypair(tmp_path: Path) -> tuple[object, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_path = tmp_path / "auth-public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_key, public_key_path


@pytest.fixture
def test_app(tmp_path: Path, keypair: tuple[object, Path]):
    _, public_key_path = keypair
    return create_app(
        str(tmp_path / "workshop.db"),
        str(tmp_path / "uploads"),
        token_public_key_path=str(public_key_path),
    )


def claims(**overrides: object) -> dict[str, object]:
    issued_at = int(time.time())
    result: dict[str, object] = {
        "sub": "student",
        "role": "STUDENT",
        "iss": "workshop-auth-backend",
        "aud": "workshop-api",
        "iat": issued_at,
        "exp": issued_at + 3600,
    }
    result.update(overrides)
    return result


def token(private_key: object, **overrides: object) -> str:
    return jwt.encode(claims(**overrides), private_key, algorithm="RS256")


def headers(private_key: object, username: str = "student", role: str = "STUDENT") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(private_key, sub=username, role=role)}"}


def test_accepts_auth_backend_jwt(test_app, keypair: tuple[object, Path]) -> None:
    private_key, _ = keypair

    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers=headers(private_key))

    assert response.status_code == 200
    assert all(task["owner"] == "student" for task in response.json())


def test_lists_seeded_tasks(test_app, keypair: tuple[object, Path]) -> None:
    private_key, _ = keypair
    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers=headers(private_key))
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_creates_task_and_summary(test_app, keypair: tuple[object, Path]) -> None:
    private_key, _ = keypair
    with TestClient(test_app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(private_key),
            json={"title": "Add tests", "description": "Improve coverage", "status": "TODO", "priority": "HIGH"},
        )
        summary = client.get("/api/summary", headers=headers(private_key))
    assert created.status_code == 201
    assert created.json()["owner"] == "student"
    assert summary.json()["total"] == 3


def test_uploads_requirement(test_app, keypair: tuple[object, Path], tmp_path: Path) -> None:
    private_key, _ = keypair
    with TestClient(test_app) as client:
        response = client.post(
            "/api/requirements",
            headers=headers(private_key),
            files={"file": ("requirements.txt", b"Login must be accessible", "text/plain")},
        )
    assert response.status_code == 201
    assert (tmp_path / "uploads" / "requirements.txt").exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "untrusted-issuer"},
        {"aud": "other-api"},
        {"exp": int(time.time()) - 1},
        {"sub": ""},
        {"role": ""},
    ],
)
def test_rejects_invalid_claims(test_app, keypair: tuple[object, Path], overrides: dict[str, object]) -> None:
    private_key, _ = keypair
    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {token(private_key, **overrides)}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}


@pytest.mark.parametrize("missing_claim", ["exp", "iat", "sub", "role"])
def test_rejects_missing_required_claims(test_app, keypair: tuple[object, Path], missing_claim: str) -> None:
    private_key, _ = keypair
    token_claims = claims()
    del token_claims[missing_claim]
    signed_token = jwt.encode(token_claims, private_key, algorithm="RS256")

    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {signed_token}"})
    assert response.status_code == 401


def test_rejects_wrong_signature(test_app) -> None:
    wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {token(wrong_private_key)}"})
    assert response.status_code == 401


def test_rejects_unsupported_algorithm(test_app, keypair: tuple[object, Path]) -> None:
    payload = claims()
    unsigned = jwt.encode(payload, "not-an-rsa-key", algorithm="HS256")
    with TestClient(test_app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {unsigned}"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path", "request_kwargs"),
    [
        ("get", "/api/tasks", {}),
        ("post", "/api/tasks", {"json": {"title": "Test"}}),
        ("get", "/api/summary", {}),
        ("post", "/api/requirements", {"files": {"file": ("requirements.txt", b"test", "text/plain")}}),
        ("get", "/api/backend-health", {}),
    ],
)
def test_protected_routes_reject_invalid_tokens(test_app, method: str, path: str, request_kwargs: dict[str, object]) -> None:
    with TestClient(test_app) as client:
        response = getattr(client, method)(
            path,
            headers={"Authorization": "Bearer malformed"},
            **request_kwargs,
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token"}


def test_fails_closed_when_public_key_is_not_configured(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": "Bearer any-token"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Token validation is not configured"}
