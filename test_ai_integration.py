from types import SimpleNamespace
from unittest.mock import patch

from api.models.scan_request import ScanRequest
from src import ai_analyst


def test_provider_presets_for_kimi_and_qwen():
    kimi = ai_analyst.build_config(api_key="k", provider="kimi")
    assert kimi.base_url == "https://api.moonshot.ai/v1"
    assert kimi.model == "kimi-k2.6"
    assert kimi.api_style == "openai"

    qwen = ai_analyst.build_config(api_key="k", provider="qwen")
    assert qwen.base_url == "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    assert qwen.model == "qwen-plus"
    assert qwen.api_style == "openai"


def test_openrouter_accepts_pasted_model_id():
    cfg = ai_analyst.build_config(
        api_key="k",
        provider="openrouter",
        model="anthropic/claude-sonnet-4",
    )
    assert cfg.base_url == "https://openrouter.ai/api/v1"
    assert cfg.model == "anthropic/claude-sonnet-4"


def test_provider_specific_env_key_wins_for_selected_provider(monkeypatch):
    monkeypatch.delenv("NETLOGIC_AI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "qwen-key")

    cfg = ai_analyst.build_config(provider="qwen")

    assert cfg.api_key == "qwen-key"
    assert cfg.base_url == "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"


def test_netlogic_ai_api_key_overrides_provider_specific_env(monkeypatch):
    monkeypatch.setenv("NETLOGIC_AI_API_KEY", "netlogic-key")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "qwen-key")

    cfg = ai_analyst.build_config(provider="qwen")

    assert cfg.api_key == "netlogic-key"


def test_ollama_does_not_send_empty_authorization_header(monkeypatch):
    captured = {}

    def fake_http_post(url, headers, payload, timeout):
        captured["headers"] = headers
        return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.delenv("NETLOGIC_AI_API_KEY", raising=False)
    monkeypatch.setattr(ai_analyst, "_http_post", fake_http_post)

    result = ai_analyst.analyze({"target": "example.com"}, ai_analyst.build_config(provider="ollama"))

    assert result.ok
    assert "Authorization" not in captured["headers"]


def test_scan_request_masks_ai_key_for_public_and_persisted_dumps():
    req = ScanRequest(target="example.com", do_ai=True, ai_provider="openai", ai_key="secret")

    assert req.public_dump()["ai_key"] == "**********"
    assert req.persisted_dump()["ai_key"] == ""
    assert req.task_dump()["ai_key"] == "secret"


def test_scan_request_normalizes_empty_ai_fields():
    req = ScanRequest(target="example.com", do_ai=True, ai_provider=" OPENAI ", ai_key=" ", ai_model=" gpt-4o-mini ")

    assert req.ai_provider == "openai"
    assert req.ai_key is None
    assert req.ai_model == "gpt-4o-mini"


def test_json_bridge_forwards_ai_options_to_engine():
    from src import json_bridge

    captured = {}

    def fake_run_scan(target, ports, args, emit=None):
        captured["target"] = target
        captured["ports"] = ports
        captured["args"] = args
        return {}

    with patch("src.engine.run_scan", fake_run_scan):
        json_bridge.run_streaming_scan(
            target="example.com",
            ports=[443],
            timeout=2,
            threads=10,
            do_osint=False,
            cidr=False,
            do_ai=True,
            ai_key="sk-test",
            ai_provider="openrouter",
            ai_model="openai/gpt-4o-mini",
            ai_base_url="",
        )

    args = captured["args"]
    assert args.ai is True
    assert args.ai_key == "sk-test"
    assert args.ai_provider == "openrouter"
    assert args.ai_model == "openai/gpt-4o-mini"


def test_remote_agent_forwards_ai_options(monkeypatch):
    import netlogic_agent

    captured = {}

    def fake_run_streaming_scan(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("src.json_bridge.run_streaming_scan", fake_run_streaming_scan)
    worker = netlogic_agent.ScanWorker(
        controller="http://controller",
        agent_id="agent",
        token="token",
        job_id="job",
        config={
            "target": "example.com",
            "ports": "quick",
            "do_ai": True,
            "ai_key": "sk-test",
            "ai_provider": "qwen",
            "ai_model": "qwen-plus",
            "ssh_user": "ubuntu",
            "ssh_port": 2222,
        },
        stop_event=SimpleNamespace(is_set=lambda: False),
    )
    worker._execute()

    assert captured["do_ai"] is True
    assert captured["ai_key"] == "sk-test"
    assert captured["ai_provider"] == "qwen"
    assert captured["ai_model"] == "qwen-plus"
    assert captured["ssh_user"] == "ubuntu"
    assert captured["ssh_port"] == 2222


# ── Upstream transient-error handling (504 etc.) ───────────────────────────────

def test_openrouter_504_error_body_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_http_post(url, headers, payload, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            # OpenRouter returns HTTP 200 with an error body on upstream timeout.
            return {"error": {"message": "Provider returned error", "code": 504}}
        return {"choices": [{"message": {"content": "recovered"}}]}

    monkeypatch.setattr(ai_analyst, "_http_post", fake_http_post)
    monkeypatch.setattr(ai_analyst.time, "sleep", lambda *_: None)  # no real backoff

    result = ai_analyst.analyze(
        {"target": "example.com"},
        ai_analyst.build_config(api_key="k", provider="openrouter", model="anthropic/claude-sonnet-4"),
    )
    assert result.ok
    assert result.markdown == "recovered"
    assert calls["n"] == 3  # two transient failures, then success


def test_openrouter_504_exhausts_retries_with_clear_message(monkeypatch):
    def fake_http_post(url, headers, payload, timeout):
        return {"error": {"message": "Provider returned error", "code": 504}}

    monkeypatch.setattr(ai_analyst, "_http_post", fake_http_post)
    monkeypatch.setattr(ai_analyst.time, "sleep", lambda *_: None)

    result = ai_analyst.analyze(
        {"target": "example.com"},
        ai_analyst.build_config(api_key="k", provider="openrouter", model="anthropic/claude-sonnet-4"),
    )
    assert not result.ok
    assert "504" in result.error
    assert "retried" in result.error.lower()
    # No longer the misleading "Empty response" label.
    assert "Empty response" not in result.error


def test_non_retryable_error_body_fails_fast_without_retry(monkeypatch):
    calls = {"n": 0}

    def fake_http_post(url, headers, payload, timeout):
        calls["n"] += 1
        return {"error": {"message": "Invalid model id", "code": 400}}

    monkeypatch.setattr(ai_analyst, "_http_post", fake_http_post)
    monkeypatch.setattr(ai_analyst.time, "sleep", lambda *_: None)

    result = ai_analyst.analyze(
        {"target": "example.com"},
        ai_analyst.build_config(api_key="k", provider="openrouter", model="bad/model"),
    )
    assert not result.ok
    assert "Invalid model id" in result.error
    assert calls["n"] == 1  # 400 is not retryable
