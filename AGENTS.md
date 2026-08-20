# AGENTS.md

## Cursor Cloud specific instructions

NetLogic is a FastAPI + in-process scan engine (`api/`, `src/`, entry `netlogic.py`) with a React/Vite dashboard (`dashboard/`). Dependencies are installed by the environment bootstrap. This file is only the non-obvious run/test caveats.

### Run

- Web app: `python3 netlogic.py --gui` on `http://localhost:8000` (FastAPI + built SPA). It writes `~/.netlogic/secrets.json` and rebuilds `dashboard/dist` when source is newer. Start it in tmux; do not `pkill` in the same compound command as the start.
- CLI scan: `python3 netlogic.py <target> [flags]`. The engine under `src/` is stdlib.

### Caveats

- Console scripts may not be on `PATH`. Prefer `python3 netlogic.py`, `python3 -m pytest`, `python3 -m bandit`.
- Clerk publishable key is inlined at **Vite build** time. `--gui` loads `VITE_*` from `dashboard/.env.example`, then `.env`, then `.env.local`. The example file has the demo publishable key. If a build still has no key, the SPA shows `MissingConfig` instead of a black screen. Never commit `.env.local`.
- Human UI login is Clerk. There is no local auth bypass. For headless scans, use the machine API:
  1. `NETLOGIC_API_KEY` in `~/.netlogic/secrets.json` (printed as the Agent key by `--gui` — machine credential, not interactive login).
  2. `POST /v1/auth/token` with `{"api_key": "..."}` → JWT.
  3. `Authorization: Bearer <jwt>` on `/v1/jobs` (not `/jobs`; that hits the SPA catch-all).
- Chrome/dbus/GPU noise from `webbrowser.open` is harmless.

### Tests / lint / build

- Python: `python3 -m pytest test_*.py -q` from repo root. `conftest.py` isolates on-disk state. Postgres tests stay skipped unless `NETLOGIC_DATABASE_URL` and `NETLOGIC_SECRETS_KEY` are set.
- SAST: `python3 -m bandit -r src api --severity-level high`.
- Dashboard: `npm --prefix dashboard test` and `npm --prefix dashboard run build` (`tsc` then `vite build`).
