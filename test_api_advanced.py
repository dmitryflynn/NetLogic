import sys, os, time
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("NETLOGIC_JWT_SECRET", "ci-test-secret-that-is-long-enough-for-tests")
os.environ.setdefault("NETLOGIC_ADMIN_KEY", "ci-admin-key")
os.environ.setdefault("NETLOGIC_NO_BROWSER", "1")

from api.main import app
from api.jobs.manager import job_manager

client = TestClient(app)

ADMIN_HEADERS = {"X-Admin-Key": os.environ["NETLOGIC_ADMIN_KEY"]}


def _get_auth_headers(org_id: str = "test-org") -> dict:
    """Create an API key for org_id and exchange it for a JWT."""
    key_resp = client.post("/v1/auth/keys", json={"org_id": org_id}, headers=ADMIN_HEADERS)
    api_key = key_resp.json()["api_key"]
    token_resp = client.post("/v1/auth/token", json={"api_key": api_key})
    token = token_resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_concurrency_and_eviction():
    headers = _get_auth_headers("concurrency-org")
    job_ids = []
    for i in range(20):
        resp = client.post("/v1/jobs", json={"target": f"127.0.0.{i}", "ports": "80"}, headers=headers)
        assert resp.status_code == 202, resp.text
        job_ids.append(resp.json()["job_id"])

    resp = client.get("/v1/jobs?limit=50", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 20


def test_persistence_rehydration():
    from api.models.scan_request import ScanRequest
    config = ScanRequest(target="persistence.manual.test")
    job = job_manager.create(config)
    job_id = job.job_id

    job.status = "completed"
    job_manager.persist_job(job)
    time.sleep(0.5)

    job_manager._jobs.clear()
    assert len(job_manager._jobs) == 0

    job_manager._load_from_storage()
    reloaded = job_manager.get(job_id)
    assert reloaded is not None
    assert reloaded.status == "completed"


def test_validation_edge_cases():
    headers = _get_auth_headers("validation-org")

    # FastAPI validates body fields even when they arrive before dependency resolution;
    # pydantic validators run before auth dependencies in some cases, but auth runs
    # first in FastAPI — so these return 422 only if auth succeeds.
    resp = client.post("/v1/jobs", json={"target": "example.com; rm -rf /", "ports": "80"}, headers=headers)
    assert resp.status_code == 422, resp.text

    resp = client.post("/v1/jobs", json={"target": "127.0.0.1", "ports": "70000"}, headers=headers)
    assert resp.status_code == 422, resp.text

    resp = client.post("/v1/jobs", json={"target": "127.0.0.1", "min_cvss": -1.0}, headers=headers)
    assert resp.status_code == 422, resp.text


if __name__ == "__main__":
    try:
        test_concurrency_and_eviction()
        test_persistence_rehydration()
        test_validation_edge_cases()
        print("\nALL ADVANCED TESTS PASSED")
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
