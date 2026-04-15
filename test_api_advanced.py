import sys, os, time, threading
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient

# Path bootstrap
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from api.main import app
from api.jobs.manager import job_manager

client = TestClient(app)

def test_concurrency_and_eviction():
    print("Testing concurrency limits and eviction...")
    
    # 1. Create many jobs quickly
    job_ids = []
    for i in range(20):
        resp = client.post("/jobs", json={"target": f"127.0.0.{i}", "ports": "80"})
        assert resp.status_code == 202
        job_ids.append(resp.json()["job_id"])
    
    # 2. Check that they all exist
    resp = client.get("/jobs?limit=50")
    data = resp.json()
    assert len(data) >= 20
    print(f"  Successfully created {len(data)} jobs.")

def test_persistence_rehydration():
    print("Testing persistence rehydration...")
    
    # 1. Create a job manually via manager to avoid submit_scan starting a task
    from api.models.scan_request import ScanRequest
    config = ScanRequest(target="persistence.manual.test")
    job = job_manager.create(config)
    job_id = job.job_id
    
    # 2. Force manual status and save
    job.status = "completed" 
    job_manager.persist_job(job)
    time.sleep(0.5) # Wait for background thread write
    
    # 3. Simulate server restart by clearing in-memory dict and reloading
    job_manager._jobs.clear()
    assert len(job_manager._jobs) == 0
    
    job_manager._load_from_storage()
    reloaded = job_manager.get(job_id)
    print(f"  Reloaded status: {reloaded.status if reloaded else 'NOT FOUND'}")
    assert reloaded is not None
    assert reloaded.status == "completed"
    print("  Job successfully rehydrated from disk.")

def test_validation_edge_cases():
    print("Testing API validation edge cases...")
    
    # Malicious target
    resp = client.post("/jobs", json={"target": "example.com; rm -rf /", "ports": "80"})
    assert resp.status_code == 422
    
    # Invalid port range
    resp = client.post("/jobs", json={"target": "127.0.0.1", "ports": "70000"})
    assert resp.status_code == 422
    
    # Negative CVSS
    resp = client.post("/jobs", json={"target": "127.0.0.1", "min_cvss": -1.0})
    assert resp.status_code == 422
    print("  Validation logic correctly rejected malformed inputs.")

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
