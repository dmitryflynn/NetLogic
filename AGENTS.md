# AGENTS.md

## Cursor Cloud specific instructions

NetLogic is a security platform with two runnable surfaces plus a large test suite. Standard
commands live in `README.md` (§How to Run, §CLI Reference, §CI / Testing) and the CI matrix in
`.github/workflows/ci.yml`; this section only records the non-obvious, Cloud-specific caveats.

### Python environment
- Dependencies are installed into a virtualenv at `/workspace/.venv` (the startup update script
  keeps it current). **Activate it before running anything Python**: `source .venv/bin/activate`.
  Without activation, the `netlogic` console script, `pytest`, `bandit`, and `pip-audit` are not on
  `PATH`.
- `python3-venv` (apt) is required to create the venv and is baked into the VM image; the update
  script does not reinstall system packages.

### Tests / lint / security gates (run from repo root, venv active)
- `python -m pytest` — full suite (~1670 tests, ~3 min). `conftest.py` already sets the required
  `NETLOGIC_JWT_SECRET` / `NETLOGIC_ADMIN_KEY` defaults and isolates all on-disk state into a temp
  dir, so no env setup is needed for the offline suite.
- `bandit -r src api --severity-level high` and `pip-audit -r requirements-api.txt` are the security
  gates from CI.
- Dashboard: from `dashboard/`, `npm test` (vitest) and `npm run build` (runs `tsc` type-check then
  `vite build`).
- The `postgres-integration` CI job (`test_pg_integration.py`, `test_pg_jobs.py`, `test_db.py`) is
  **optional** and NOT run by default — it needs a live Postgres plus `NETLOGIC_DATABASE_URL` and a
  Fernet `NETLOGIC_SECRETS_KEY`. The app and the rest of the suite run fully in-memory without any
  database.

### Running the web app
- `netlogic --gui` (blocking) serves the FastAPI backend + the built React SPA on
  `http://localhost:8000`, auto-generates secrets into `~/.netlogic/secrets.json`, and prints a
  machine **Agent key**. Run it in a persistent tmux session.
- It auto-opens a browser via `webbrowser.open`, which spams harmless `dbus`/`gpu`/Chrome errors in
  the log — ignore them; they do not affect the server.
- **Dashboard UI needs a Clerk publishable key at BUILD time.** `netlogic --gui` builds
  `dashboard/dist` **without** it, so the SPA throws `Missing VITE_CLERK_PUBLISHABLE_KEY` and renders
  a blank page. To get a working UI, rebuild with the key from `.env.example` (non-secret, demo Clerk
  instance):
  `cd dashboard && VITE_CLERK_PUBLISHABLE_KEY=pk_test_dHJ1c3R5LWh1bXBiYWNrLTQ1LmNsZXJrLmFjY291bnRzLmRldiQ npm run build`
  The backend serves whatever is in `dashboard/dist` (no server restart needed after a rebuild).
- Alternatively run the Vite dev server for hot reload: `cd dashboard && npm run dev` (port 5173,
  proxies `/v1` → `localhost:8000`); still needs `VITE_CLERK_PUBLISHABLE_KEY` in the environment.

### Testing scans without interactive Clerk login
Human UI login is Clerk (third-party). For automated/headless verification, use the machine auth
path instead — no Clerk account required:
1. Read the API key from `~/.netlogic/secrets.json` (`NETLOGIC_API_KEY`).
2. `POST /v1/auth/token {"api_key": "..."}` → returns a JWT in the `token` field.
3. `POST /v1/jobs` with `Authorization: Bearer <jwt>` to launch a scan (e.g. target `127.0.0.1`),
   then poll `GET /v1/jobs/{id}` until `status=completed`. The in-process scan agent started by the
   backend executes the job.
