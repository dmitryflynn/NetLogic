# AGENTS.md

## Cursor Cloud specific instructions

NetLogic is a network-security web app: a **FastAPI backend + in-process scan engine** (`api/`, `src/`, entry `netlogic.py`) plus a **React/Vite/TypeScript dashboard** (`dashboard/`). The dependency-install step is handled by the environment update script, so the notes below cover only non-obvious startup/run caveats.

### Services & how to run them

- **Web app (backend + dashboard):** `python3 netlogic.py --gui` (serves FastAPI + the built React SPA on `http://localhost:8000`). This is the only supported way to run the web app. It auto-generates secrets into `~/.netlogic/secrets.json` and, on first run, builds `dashboard/dist` if missing/stale. Runs uvicorn in the foreground — start it in a background/tmux terminal.
- **CLI scan (no server):** `python3 netlogic.py <target> [flags]` (e.g. `--full`, `--tls`, `--probe`). The scan engine under `src/` is pure stdlib.

### Non-obvious caveats

- **Console scripts aren't on PATH.** `pip install -e .` puts the `netlogic` (and `pytest`, `bandit`) launchers in `~/.local/bin`, which is not on PATH. Invoke via the module form instead: `python3 netlogic.py ...`, `python3 -m pytest ...`, `python3 -m bandit ...`.
- **Dashboard requires a Clerk publishable key at build time.** `dashboard/src/main.tsx` throws `Missing VITE_CLERK_PUBLISHABLE_KEY` when the key is absent, producing a blank page. Create `dashboard/.env.local` (git-ignored) with the non-secret publishable key from `.env.example` before building/running the UI:
  `VITE_CLERK_PUBLISHABLE_KEY=pk_test_dHJ1c3R5LWh1bXBiYWNrLTQ1LmNsZXJrLmFjY291bnRzLmRldiQ`
  If you rebuild after adding the key, delete `dashboard/dist` (or touch a source file) so `netlogic --gui`'s staleness check rebuilds it.
- **Dashboard login is gated by Clerk (OIDC).** The human UI redirects to a Clerk sign-in and needs a real account to reach the app; there is no local bypass. To exercise scans without a UI login, drive the API directly.
- **API auth is a two-step Bearer flow.** All app routes are under `/v1` (e.g. `/v1/jobs`), not `/` (hitting `/jobs` returns 405 from the SPA catch-all). Exchange the machine API key (printed by `--gui`, stored in `~/.netlogic/secrets.json` as `NETLOGIC_API_KEY`) for a JWT via `POST /v1/auth/token {"api_key": "..."}`, then send `Authorization: Bearer <jwt>`. Start a scan with `POST /v1/jobs {"target": "...", "ports": "custom=22,80,443"}` and poll `GET /v1/jobs/<id>`.

### Tests / lint / build

- **Python tests:** `python3 -m pytest test_*.py -q` (test isolation is set up in `conftest.py`; needs no external services — Postgres tests are structural offline). ~1690 tests, takes a few minutes.
- **Security gate (SAST):** `python3 -m bandit -r src api --severity-level high`.
- **Dashboard build + type-check:** `npm --prefix dashboard run build` (runs `tsc` then `vite build`).
- **Dashboard tests:** `npm --prefix dashboard test` (vitest).
- **Live Postgres integration** (`test_pg_integration.py`, `test_pg_jobs.py`, `test_db.py`) needs a running Postgres and `NETLOGIC_DATABASE_URL` + `NETLOGIC_SECRETS_KEY`; skipped by default. The app runs fully in-memory when `NETLOGIC_DATABASE_URL` is unset.
