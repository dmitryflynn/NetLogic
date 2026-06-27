"""
Regression: config_from_env() must fall back to ~/.netlogic/secrets.json.

This silently broke because _secrets_dict() referenced `Path` without importing
it; the NameError was swallowed by a bare `except Exception: return {}`, so the
GUI/desktop AI config (stored in secrets.json, no env vars) never loaded. Pin
the behavior so it can't regress.
"""
import importlib
import json


def test_config_reads_from_secrets_json(tmp_path, monkeypatch):
    (tmp_path / "secrets.json").write_text(json.dumps({
        "NETLOGIC_AI_PROVIDER": "openai",
        "NETLOGIC_AI_API_KEY": "sk-from-secrets-file",
        "NETLOGIC_AI_MODEL": "gpt-4o-mini",
    }))
    monkeypatch.setenv("NETLOGIC_DATA_DIR", str(tmp_path))
    for k in ("NETLOGIC_AI_PROVIDER", "NETLOGIC_AI_API_KEY", "NETLOGIC_AI_MODEL", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)

    import src.ai_analyst as a
    importlib.reload(a)
    cfg = a.config_from_env()
    assert cfg.api_key == "sk-from-secrets-file"
    assert cfg.provider == "openai"
    assert cfg.model == "gpt-4o-mini"


def test_env_overrides_secrets_json(tmp_path, monkeypatch):
    (tmp_path / "secrets.json").write_text(json.dumps({"NETLOGIC_AI_API_KEY": "sk-file"}))
    monkeypatch.setenv("NETLOGIC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NETLOGIC_AI_API_KEY", "sk-env-wins")
    monkeypatch.setenv("NETLOGIC_AI_PROVIDER", "openrouter")

    import src.ai_analyst as a
    importlib.reload(a)
    assert a.config_from_env().api_key == "sk-env-wins"
