"""Dev-only launcher: sets a local admin key before starting the API server.

Not for production — NETLOGIC_ADMIN_KEY here is a throwaway dev secret so the
auth flow (API key -> JWT) can be exercised locally without a real Clerk setup.

Runnable from any cwd: fixes sys.path/cwd to the project root (this file's
parent directory) so `import api.main` resolves regardless of launcher cwd.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

os.environ.setdefault("NETLOGIC_ADMIN_KEY", "dev-local-admin-key-not-for-prod-0001")
os.environ.setdefault("NETLOGIC_NO_BROWSER", "1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=False)
